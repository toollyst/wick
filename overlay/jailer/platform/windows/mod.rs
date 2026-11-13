// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! Windows backend of the jailer's host primitives (see `platform`).
//!
//! Windows has no chroot, no user switch from a non-elevated process and no
//! exec. What the jailer does instead, each measured on WHP hardware
//! (docs/ROADMAP.md, M5):
//!
//! - **The jail's root is a drive of its own** ([`chroot`](super::chroot)):
//!   `DefineDosDevice` maps a free drive letter to the jail directory and the
//!   current directory becomes its root, so upstream's absolute paths
//!   (`/dev`, `/run/firecracker.socket`, the pid file) and the ones
//!   Firecracker is given resolve inside the jail, files and `AF_UNIX`
//!   sockets alike. Other drives stay reachable by their letter: confinement
//!   is the token's.
//! - **The jailed identity is a restricted token** instead of `--uid`/`--gid`
//!   (Windows has no numeric ids; they are recorded in `WICK_JAIL` only): the
//!   user's privileges removed, the user's own SID left out of the
//!   restricting SIDs, so the user's files are denied, and the jail's
//!   integrity level ([`JAIL_INTEGRITY_SID`], between low and medium), so
//!   nothing at medium integrity can be written. WHP works for such a process
//!   (it is refused inside an AppContainer). The process starts with an
//!   initial impersonation token on its main thread, the same restricted
//!   token with the user's SID, for the loader to initialise; Firecracker
//!   reverts to the lockdown token first thing (`vmm::ext::jail`), the
//!   pattern of the Chromium sandbox.
//! - **Each jail has a SID of its own** (random), the Windows counterpart of a
//!   per-microVM uid: the token's only restricting SID that its directory
//!   grants. The other restricting SIDs are groups every process of the
//!   session has (Everyone, Users, Authenticated Users, Interactive). Not the
//!   logon SID: the default DACL of the user's processes grants it read and
//!   execute, which for a process includes `PROCESS_TERMINATE`, so with it a
//!   jailed process could end any process of the user (measured); only the
//!   initial impersonation token has it, for process start-up.
//! - **No other process is in reach**, as in a PID namespace: the token opens
//!   no process or thread outside the jail (the user's, another jail's, the
//!   jailer, SYSTEM's), and a process snapshot shows a process below medium
//!   integrity no other process. Firecracker is not attached to the jailer's
//!   console ([`console`]), so it can neither send console control events to
//!   the console's processes nor type into it; the jailer relays the console
//!   through pipes. Windows still tells whether a pid is in use (`OpenProcess`
//!   fails differently), as `kill(pid, 0)` does outside a PID namespace.
//! - **The jail directory** is protected from what its parent grants and
//!   grants full access, inherited, to the jail's SID, the user, SYSTEM and
//!   the administrators. Its mandatory label is the jail's integrity level,
//!   no read, write or execute up: a process of the user below it (a
//!   low-integrity one, as a browser's sandbox runs) cannot open the jail's
//!   files or API socket, nor the jailed process, although the user's SID
//!   grants them; Firecracker, at that level, and the operator, above it, can.
//! - **cgroups are a Job Object** ([`cgroup`](super::cgroup)): job memory
//!   limit, CPU rate hard cap (from Firecracker's start, as a cgroup's
//!   limit holds from the exec) or CPU weight, processor affinity; the job
//!   kills Firecracker when the jailer goes and limits its UI access.
//! - **The freezer** ([`freezer`]): upstream's cgroup freezer files next to
//!   the jail's root, for every jail, kept by the jailer, which freezes and
//!   thaws the job as a whole.
//! - **No exec**: the jailer starts Firecracker suspended in the job with the
//!   tokens, waits for it, removes the jail's drive and exits with its status.
//! - **`--daemonize`** ([`daemonize`]): Windows has no fork, so the jailer
//!   relaunches itself detached, without the flag, and returns 0; the
//!   detached jailer builds the jail and runs Firecracker with no console.
//! - **`--new-pid-ns`** ([`new_pid_ns`]): the isolation is every jail's
//!   (above); the jailer hands over to a relaunched keeper and returns 0 once
//!   Firecracker runs, its pid in the pid file, as upstream's returns after
//!   the clone.
//! - **`--netns <dir>`** ([`netns`]): the jail's network is the directory
//!   named, which grants no jail anything; Firecracker makes its network
//!   endpoints in the jail's own directory in it, `<dir>\<id>`, which only
//!   the jail and the operator reach ([`jail_network`]); and the jail's copy
//!   of Firecracker gets no IP networking at all (Windows Filtering
//!   Platform). Needs an elevated jailer, as `setns` needs root.
//!
//! - **`--resource-limit no-file=`** ([`install_resource_limits`]): each
//!   process of the jail gets the limit in `WICK_NO_FILE` (upstream's 2048
//!   when none is given) and counts it in handles, where Linux counts
//!   descriptors; wick's POSIX layer fails a call that would make
//!   descriptors past it with `EMFILE`, as past `RLIMIT_NOFILE`
//!   (crates/compat/libc, `wick_nofile`). It is enforced inside the jailed
//!   process, so it does not bound a compromised one.
//!
//! Refused, never accepted without effect: `--resource-limit fsize=`
//! (Windows cannot limit file sizes).

use std::ffi::{CStr, OsStr};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    DuplicateHandle, ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER, FILETIME, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE, STILL_ACTIVE, WAIT_OBJECT_0,
    LocalFree, SetHandleInformation,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DACL_SECURITY_INFORMATION, DuplicateTokenEx,
    LUID_AND_ATTRIBUTES, LookupPrivilegeNameW, TOKEN_PRIVILEGES, TokenPrivileges,
    GetLengthSid, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl, GetTokenInformation,
    LABEL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS,
    TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_OWNER, TOKEN_QUERY,
    TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenDefaultDacl, TokenGroups, TokenImpersonation,
    TokenIntegrityLevel, TokenOwner, TokenUser, PROTECTED_DACL_SECURITY_INFORMATION, ACL,
    TOKEN_ELEVATION_TYPE, TOKEN_LINKED_TOKEN, TokenElevationType, TokenElevationTypeFull, TokenLinkedToken,
};
use windows_sys::Win32::Storage::FileSystem::{
    DDD_EXACT_MATCH_ON_REMOVE, DDD_RAW_TARGET_PATH, DDD_REMOVE_DEFINITION, DefineDosDeviceW, GetLogicalDrives,
};
#[cfg(test)]
use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, INHERITED_ACE, OBJECT_INHERIT_ACE};
#[cfg(test)]
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED,
    JOB_OBJECT_LIMIT_AFFINITY, JobObjectGroupInformationEx,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP,
    JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, GetProcessTimes, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, SetEvent,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, SetThreadToken, TerminateProcess,
    UpdateProcThreadAttribute, WaitForMultipleObjects, WaitForSingleObject,
};

pub(crate) mod cgroup_values;
mod console;
mod freezer;
mod large_pages;
mod netns;
pub(crate) mod parent;

pub(crate) use super::freezer_values::{State as FreezerState, Version as FreezerVersion, parse_start as parse_freezer_start};

/// `SE_GROUP_INTEGRITY` (winnt.h).
const SE_GROUP_INTEGRITY: u32 = 0x20;
/// `SE_GROUP_LOGON_ID` (winnt.h).
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

use crate::JailerError;

/// Environment variable through which Firecracker takes the jail over
/// (`vmm::ext::jail::ENV`).
const JAIL_ENV: &str = "WICK_JAIL";
/// Environment variable through which Firecracker takes the jail's network
/// over (`vmm::ext::jail::NETNS_ENV`): the directory of its endpoints.
const NETNS_ENV: &str = "WICK_NETNS";
/// The path of the socket the API process listens on for Firecracker, to
/// the API process (`vmm::ext::api_process::LINK_ENV`)...
const API_LINK_ENV: &str = "WICK_API_LINK";
/// ...and to Firecracker (`vmm::ext::api_process::WAITING_ENV`).
const API_WAITING_ENV: &str = "WICK_API_WAITING";
/// Firecracker's handle to the API process, `SYNCHRONIZE` and
/// `PROCESS_DUP_HANDLE` (`vmm::ext::api_process::API_PROCESS_ENV`).
const API_PROCESS_ENV: &str = "WICK_API_PROCESS";
/// Environment variable through which each process of the jail gets
/// `--resource-limit no-file=`, a number of handles (the compat libc's
/// `wick_nofile::ENV`, wick-os's `nofile::ENV`).
const NO_FILE_ENV: &str = "WICK_NO_FILE";
/// Upstream's default `no-file` (src/jailer/src/resource_limits.rs,
/// `NO_FILE`, private there), when none is given.
const NO_FILE_DEFAULT: u64 = 2048;
/// `PROCESS_DUP_HANDLE` (winnt.h).
const PROCESS_DUP_HANDLE: u32 = 0x0040;
/// `SYNCHRONIZE` (winnt.h).
const SYNCHRONIZE: u32 = 0x0010_0000;
/// Bytes every binary that takes the jail over carries
/// (`vmm::ext::jail::HANDOVER_MARK`): without it, a program would keep the
/// initial impersonation token (the user's SID) on its main thread.
const HANDOVER_MARK: &[u8] = b"wick-jail-handover:v1\0";
/// Firecracker's temporary directory in the jail: memfds are unlinked files
/// there on Windows (crates/compat/memfd); on Linux they are kernel objects.
const JAIL_TMP: &str = "tmp";

/// Restricting SIDs of the lockdown token besides the jail's own
/// ([`vm_sid`]): groups any process of the session has, never the user's own
/// SID nor the logon SID (module documentation). Each grants only what every
/// process of the session is granted anyway; the jail's SID is the only one
/// its directory grants.
const RESTRICTING_SIDS: [&str; 4] = [
    "S-1-1-0",      // Everyone
    "S-1-5-32-545", // Users
    "S-1-5-11",     // Authenticated Users
    "S-1-5-4",      // Interactive
];

/// The SID of this jail, which only its tokens have (as a restricting SID):
/// the Windows counterpart of a per-microVM uid. Random, in the resource
/// manager authority (S-1-9), where no account lives. Without one, every
/// jailed process had the same restricting SIDs and the jail directories
/// granted them all: one microVM could read and write another's jail and
/// connect to its API socket (measured with tools/windows/jail-probe.rs).
fn vm_sid() -> &'static str {
    static SID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SID.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        // `RandomState` keys come from the system's random number generator.
        let word = |n: u64| {
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_u64(n);
            h.finish()
        };
        let (a, b) = (word(1), word(2));
        #[allow(clippy::cast_possible_truncation)]
        let parts = [a as u32, (a >> 32) as u32, b as u32, (b >> 32) as u32];
        format!("S-1-9-{}-{}-{}-{}", parts[0], parts[1], parts[2], parts[3])
    })
}

/// The default DACL of both tokens: what the process creates (its own process
/// and threads first) carries it: SYSTEM, the jail's SID and the owner (the
/// process objects of a jail's Firecracker and API process read
/// `D:(A;;0x1fffff;;;SY)(A;;0x1fffff;;;<jail SID>)(A;;0x1fffff;;;OW)`, label
/// `S-1-16-6144` no-write-up/no-read-up, measured on Windows 11 26H2). The
/// operator opens them with every right. A process of the jail opening its
/// sibling for `PROCESS_DUP_HANDLE` is refused all the same (access denied,
/// measured in `jailer-test.ps1 api`); why is not measured, and the
/// Firecracker-to-API-process link does not depend on it
/// (`vmm::ext::api_process`, `WICK_API_PROCESS`).
fn default_dacl() -> String {
    format!("D:(A;;GA;;;SY)(A;;GA;;;{})(A;;GA;;;OW)", vm_sid())
}

/// The jail directory, protected from what its parent grants (`C:\`'s
/// Authenticated Users: Modify would let every jail in): full access for
/// SYSTEM, the administrators, the user (who also needs `WRITE_OWNER` for
/// the label below) and the jail's SID, inherited.
fn jail_dacl(user: &str) -> String {
    format!(
        "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;FA;;;{})",
        vm_sid()
    )
}
/// Low mandatory label, inherited, no write up.
const JAIL_LABEL: &str = "S:(ML;OICI;NWNRNX;;;S-1-16-6144)";
/// The jailed process's integrity level: above low (0x1000), so that a
/// low-integrity process of the same user, which holds the user's SID the
/// jail directory grants, is kept out by the jail's label, and below medium
/// (0x2000), so that the jailed process writes nothing at medium integrity.
/// Windows compares levels as numbers; 0x1800 has no name of its own.
const JAIL_INTEGRITY_SID: &str = "S-1-16-6144";

/// What the Windows backend refuses, or a Windows step that failed.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error(
        "--{0} is not supported on Windows: {1}. The jailer never accepts an isolation option it \
         cannot enforce."
    )]
    Unsupported(&'static str, &'static str),
    #[error(
        "--cgroup {0} is not supported on Windows (supported: memory.max, cpu.max, cpu.weight, \
         cpu.weight.nice, cpuset.cpus and cpuset.mems with --cgroup-version 2; \
         memory.limit_in_bytes, cpu.cfs_quota_us, cpu.cfs_period_us, cpu.shares, cpuset.cpus, \
         cpuset.mems and freezer.state with --cgroup-version 1). The jailer never accepts a limit it cannot enforce."
    )]
    UnsupportedCgroup(String),
    #[error("--cgroup {0} is refused on Windows: {1}. The jailer never accepts a limit it cannot enforce.")]
    ImpossibleCgroup(String, &'static str),
    #[error("--cgroup {0}: {1}")]
    CgroupValue(String, &'static str),
    #[error("--parent-cgroup {0:?}: {1}")]
    Parent(String, String),
    #[error(
        "--resource-limit {0} is not supported on Windows: {1}. The jailer never accepts a limit \
         it cannot enforce."
    )]
    UnsupportedLimit(&'static str, &'static str),
    #[error("No Windows equivalent for the device {0:?} in the jail")]
    UnsupportedDevice(String),
    #[error("Failed to set up the jail at {0:?}: {1}: {2}")]
    Jail(PathBuf, &'static str, io::Error),
    #[error("No free drive letter for the jail's root")]
    NoDriveLetter,
    #[error(
        "{0:?} cannot take the jail over (it is not a wick Firecracker build), so its main thread \
         would keep the user's identity"
    )]
    NoHandover(PathBuf),
    #[error("Failed to start the jailed process: {0}: {1}")]
    Spawn(&'static str, io::Error),
    #[error("--netns {0:?}: {1}")]
    Netns(PathBuf, String),
    #[error("The jail's freezer: {0}")]
    Freezer(String),
}

impl From<HostError> for JailerError {
    fn from(err: HostError) -> Self {
        JailerError::Host(err)
    }
}

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// A path without the `\\?\` prefix `canonicalize` gives on Windows, which
/// `DefineDosDevice` and command lines do not take.
fn plain(path: &Path) -> PathBuf {
    let s = path.as_os_str().to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_owned(),
    }
}

/// The jail the jailer entered: its directory, the drive mapped to it and
/// the files it shares with other jails ([`share_with_jail`]).
struct Jail {
    root: PathBuf,
    drive: String,
    shared: Vec<PathBuf>,
}

static JAIL: Mutex<Option<Jail>> = Mutex::new(None);

/// The Job Object limits, from the cgroup configuration.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Limits {
    pub memory_bytes: Option<u64>,
    /// Hundredths of a percent of all processors (`CpuRate`).
    pub cpu_rate: Option<u32>,
    /// The job's CPU weight, 1 to 9 (`Weight`); never with `cpu_rate`.
    pub cpu_weight: Option<u32>,
    /// The processors the job runs on: an affinity mask per processor group.
    pub cpus: Option<Vec<(u16, u64)>>,
    /// Large pages the jailer gives Firecracker in all, in bytes
    /// (`hugetlb.2MB.max`): the large-page broker refuses past it.
    pub large_page_bytes: Option<u64>,
}

static LIMITS: Mutex<Limits> = Mutex::new(Limits {
    memory_bytes: None,
    cpu_rate: None,
    cpu_weight: None,
    cpus: None,
    large_page_bytes: None,
});

pub(crate) fn set_limits(limits: Limits) {
    *LIMITS.lock().unwrap() = limits;
}

/// The jail's cgroup version, whose freezer files it gets ([`freezer`]).
pub(crate) fn set_cgroup_version(version: FreezerVersion) {
    freezer::set_version(version);
}

/// `--cgroup freezer.state=<state>` (v1), at the cgroup step: the freezer's
/// files are made now and, for `FROZEN`, the jailer waits here until they
/// say `THAWED`, as on Linux the jailer freezes itself at this step
/// ([`freezer`]).
pub(crate) fn freezer_at_cgroup_step(state: FreezerState) -> Result<(), JailerError> {
    let dir = jail_dir_from_args()?;
    freezer::at_cgroup_step(&dir, state).map_err(|e| HostError::Freezer(e.to_string()).into())
}

/// The jail's directory (`<chroot-base>\<exec file name>\<id>`), as
/// `Env::new` makes it from the same command line (the cgroup step is not
/// given it; upstream's `main` has made it already).
fn jail_dir_from_args() -> Result<PathBuf, JailerError> {
    let mut parser = crate::build_arg_parser();
    parser.parse_from_cmdline().map_err(JailerError::ArgumentParsing)?;
    let args = parser.arguments();
    let value = |name: &'static str| {
        args.single_value(name)
            .cloned()
            .ok_or_else(|| HostError::Freezer(format!("no --{name} on the command line")))
    };
    let base = value("chroot-base-dir")?;
    let exec = value("exec-file")?;
    let base = std::fs::canonicalize(&base).map_err(|e| JailerError::Canonicalize(PathBuf::from(&base), e))?;
    let exec = std::fs::canonicalize(&exec).map_err(|e| JailerError::Canonicalize(PathBuf::from(&exec), e))?;
    let name = exec.file_name().ok_or_else(|| JailerError::ExtractFileName(exec.clone()))?;
    Ok(plain(&base.join(name).join(value("id")?)))
}

/// The freezer's files made at the cgroup step, handed to the jailer this
/// one starts again (`--daemonize`, `--new-pid-ns`): the handle it inherits.
fn freezer_handover() -> io::Result<Vec<OwnedHandle>> {
    Ok(freezer::handover()?.into_iter().collect())
}

/// The jail's network (`--netns`): the directory of its endpoints, and the
/// filter session that will deny the jail IP.
static NETNS: Mutex<Option<(PathBuf, netns::NetFilter)>> = Mutex::new(None);

/// `--netns <dir>`: the jail's network is the directory `dir`, which must
/// exist, as the namespace file must on Linux (`netns` module documentation).
/// Opens the filter session, which refuses a jailer that is not elevated,
/// here, where `setns` fails on Linux; the directory is opened to the jail
/// and the filters added when Firecracker starts ([`exec`]).
pub fn join_netns(path: &str) -> Result<(), JailerError> {
    let dir = std::fs::canonicalize(path)
        .map(|p| plain(&p))
        .map_err(|e| HostError::Netns(PathBuf::from(path), format!("cannot open the network directory: {e}")))?;
    if !dir.is_dir() {
        return Err(HostError::Netns(dir, "a network is a directory of endpoints".into()).into());
    }
    let filter = netns::NetFilter::open().map_err(|e| HostError::Netns(dir.clone(), e.to_string()))?;
    *NETNS.lock().unwrap() = Some((dir, filter));
    Ok(())
}

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_DENIED_ACE_TYPE` (winnt.h; in
/// windows-sys under `SystemServices`, a feature the jailer does not take).
#[cfg(test)]
const ACCESS_ALLOWED_ACE_TYPE: u32 = 0;
#[cfg(test)]
const ACCESS_DENIED_ACE_TYPE: u32 = 1;

/// The entries of the DACL of `path`: ACE type, flags, access mask and the
/// SID as text. The SID comes from `ConvertSidToStringSidW`, `S-1-...`
/// always; SDDL writes a well-known account as its alias (CI's Windows
/// runner is the built-in Administrator, which SDDL writes as `LA`, not
/// `S-1-5-21-...-500`), so a text comparison on SDDL misses it.
#[cfg(test)]
fn dacl_entries(path: &Path) -> io::Result<Vec<(u8, u8, u32, String)>> {
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce, GetAclInformation,
    };
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path and out-pointers.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    let entries = (|| {
        if acl.is_null() {
            // No DACL: everything is allowed; nothing to keep.
            return Ok(Vec::new());
        }
        let mut info = ACL_SIZE_INFORMATION { AceCount: 0, AclBytesInUse: 0, AclBytesFree: 0 };
        let size = u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap();
        // SAFETY: the ACL lives in `sd`; a structure of the size passed.
        if unsafe { GetAclInformation(acl, (&raw mut info).cast(), size, AclSizeInformation) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut entries = Vec::with_capacity(info.AceCount as usize);
        for i in 0..info.AceCount {
            let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
            // SAFETY: an index below the count read above; an out-pointer.
            if unsafe { GetAce(acl, i, &mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: GetAce gave an ACE, whose header comes first.
            let header = unsafe { *ace.cast::<ACE_HEADER>() };
            let (mask, sid) = if u32::from(header.AceType) == ACCESS_ALLOWED_ACE_TYPE
                || u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE
            {
                // SAFETY: an allow or deny ACE has the mask and the SID after
                // the header (ACCESS_DENIED_ACE is laid out as ACCESS_ALLOWED_ACE).
                let a = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                (a.Mask, sid_string((&raw const a.SidStart).cast_mut().cast())?)
            } else {
                (0, String::new())
            };
            entries.push((header.AceType, header.AceFlags, mask, sid));
        }
        Ok(entries)
    })();
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    entries
}

/// The DACL of `path` as SDDL (`D:...`), for the tests: see [`dacl_entries`]
/// for why nothing is compared against it.
#[cfg(test)]
fn dacl_sddl(path: &Path) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    };
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path and an out-pointer.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    let mut text: *mut u16 = std::ptr::null_mut();
    let mut len = 0u32;
    // SAFETY: the descriptor read above; out-pointers.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut text, &mut len)
    };
    let err = io::Error::last_os_error();
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    if ok == 0 {
        return Err(err);
    }
    // SAFETY: `len` characters allocated by the conversion, freed here.
    let sddl = unsafe {
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len as usize));
        LocalFree(text.cast());
        s
    };
    Ok(sddl.trim_end_matches('\0').to_owned())
}

/// The longest endpoint name Firecracker makes in a network directory
/// (`platform::net`: names shorter than `IFNAMSIZ`, 16).
const ENDPOINT_NAME_MAX: usize = 15;
/// `sockaddr_un`'s path with its NUL (afunix.h, `UNIX_PATH_MAX`): an endpoint's
/// path must be shorter (`platform::net` refuses a longer one).
const UNIX_PATH_MAX: usize = 108;

/// The owner of `path`, as text.
fn owner_sid(path: &Path) -> io::Result<String> {
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut owner: PSID = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path and out-pointers.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    let sid = sid_string(owner);
    // SAFETY: allocated by GetNamedSecurityInfoW; `owner` points into it.
    unsafe { LocalFree(sd) };
    sid
}

/// What a jail holds of its network (`--netns`) while Firecracker runs: the
/// directory of its own its endpoints are made in, named to Firecracker
/// (`vmm::ext::jail::NETNS_ENV`), open without `FILE_SHARE_DELETE` so that a
/// second jail of the same id is refused while this one lives. The jailer
/// keeps it until it ends, with Firecracker.
#[derive(Debug)]
struct JailNetwork {
    dir: PathBuf,
    _lock: std::fs::File,
}

/// Gives the jail `id` its own directory in the network directory
/// `network`: `<network>\<id>`, where Firecracker makes its endpoints
/// (`platform::net`), as a TAP is its owner's on Linux (drivers/net/tun.c:
/// `tun_not_capable` refuses another user's attach, `tun_attach` a second
/// one with EBUSY).
///
/// - The network directory grants no jail anything: SYSTEM, the
///   administrators, the user and the directory's owner (the operator, whose
///   switch reaches the endpoints), protected from what its parent grants
///   (`C:\` gives Authenticated Users, which every jail's token holds, Modify).
///   An entry an earlier jailer gave a jail there goes. A jail reaches its
///   own directory through it by its traversal privilege
///   (`SeChangeNotifyPrivilege`, the one the jail keeps), and can neither
///   list it nor make a name in it, so it cannot take a later jail's name or
///   directory first.
/// - The jail's directory holds those and the jail's SID, protected and
///   labelled with the jail's integrity level, so that the jail can make its
///   endpoints there (an object without a label is medium, which a jail may
///   not write to). No other jail reaches it: none can connect to an
///   endpoint there (AF_UNIX `connect` needs write access to the socket's
///   file), delete one or take its name.
/// - It is opened without `FILE_SHARE_DELETE` first: while a jail of the id
///   runs, a second one is refused as busy (EBUSY on Linux) and the first
///   keeps its endpoints. A link or a file in its place is refused. Both
///   DACLs are written through handles ([`set_security_of`]), so a jail
///   starting does not open the directories of the jails running. What a
///   jail of the id that ended left (its endpoints) is removed; the
///   directory itself is kept when the jail ends, as upstream keeps the
///   jail's root.
/// - A network path whose endpoints could not be named within
///   `sockaddr_un`'s 108 bytes is refused before anything is made (Linux
///   names a TAP, not a path).
fn jail_network(network: &Path, id: &OsStr) -> Result<JailNetwork, HostError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };
    /// `ERROR_SHARING_VIOLATION` (winerror.h).
    const SHARING_VIOLATION: i32 = 32;
    let refuse = |why: String| HostError::Netns(network.to_owned(), why);
    let fail = |what: String, e: io::Error| HostError::Netns(network.to_owned(), format!("{what}: {e}"));
    let dir = network.join(id);
    if dir.as_os_str().len() + 1 + ENDPOINT_NAME_MAX >= UNIX_PATH_MAX {
        return Err(refuse(format!(
            "the jail's network directory {} is too long a path: an endpoint's path, the directory and a \
             name of up to {ENDPOINT_NAME_MAX} characters, must be shorter than sockaddr_un's {UNIX_PATH_MAX} bytes",
            dir.display()
        )));
    }
    let user = user_sid().map_err(|e| fail("the user's SID".into(), e))?;
    let owner = owner_sid(network).map_err(|e| fail("the network directory's owner".into(), e))?;
    let mut operators = vec!["S-1-5-18".to_owned(), "S-1-5-32-544".to_owned(), user];
    if !operators.contains(&owner) {
        operators.push(owner);
    }
    let dacl = |jail: Option<&str>| {
        let mut dacl = "D:PAI".to_owned();
        for sid in operators.iter().map(String::as_str).chain(jail) {
            dacl.push_str(&format!("(A;OICI;FA;;;{sid})"));
        }
        dacl
    };
    // Written whole, the same by every jailer of the user: no other jailer's
    // change is lost, and the running jails' directories in it, each with a
    // protected DACL of its own, are not touched.
    let whole = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(network)
        .map_err(|e| fail("open the network directory".into(), e))?;
    set_security_of(whole.as_raw_handle(), &dacl(None), false)
        .map_err(|e| fail("close the network directory to every jail".into(), e))?;
    drop(whole);
    match std::fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(fail(format!("make {}", dir.display()), e)),
    }
    let lock = std::fs::OpenOptions::new()
        .access_mode(DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&dir)
        .map_err(|e| {
            if e.raw_os_error() == Some(SHARING_VIOLATION) {
                refuse(format!(
                    "{} is busy: a jail of id {} is running and holds it ({e})",
                    dir.display(),
                    id.to_string_lossy()
                ))
            } else {
                fail(format!("open {}", dir.display()), e)
            }
        })?;
    // SAFETY: zeroed is a valid value of the plain structure.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: an open handle and a structure to fill.
    if unsafe { GetFileInformationByHandle(lock.as_raw_handle(), &mut info) } == 0 {
        return Err(fail(format!("read {}", dir.display()), last_error()));
    }
    // Held, it can be neither renamed nor removed: the checks hold for the
    // path from here on.
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(refuse(format!("{} is not a directory of its own (a link or a file)", dir.display())));
    }
    // Through the handle held: the object checked above. What is in it now
    // goes next; what Firecracker makes there inherits this.
    set_security_of(lock.as_raw_handle(), &dacl(Some(vm_sid())), false)
        .map_err(|e| fail(format!("give {} to the jail", dir.display()), e))?;
    set_security_of(lock.as_raw_handle(), JAIL_LABEL, true).map_err(|e| fail(format!("label {}", dir.display()), e))?;
    let left = std::fs::read_dir(&dir).map_err(|e| fail(format!("read {}", dir.display()), e))?;
    for entry in left {
        let entry = entry.map_err(|e| fail(format!("read {}", dir.display()), e))?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| fail(format!("read {}", path.display()), e))?;
        if kind.is_dir() {
            return Err(refuse(format!("{} holds a directory, which no jail makes there", dir.display())));
        }
        std::fs::remove_file(&path)
            .map_err(|e| fail(format!("remove {}, which a jail of id {} left", path.display(), id.to_string_lossy()), e))?;
    }
    Ok(JailNetwork { dir, _lock: lock })
}

/// The variable that tells a relaunched jailer it is the keeper of a
/// `--new-pid-ns` jail, holding the value of the event it sets once
/// Firecracker runs ([`new_pid_ns`]).
const KEEPER_ENV: &str = "WICK_JAILER_KEEPER";

/// The keeper's event (a handle value), until it is set.
static KEEPER_EVENT: Mutex<Option<usize>> = Mutex::new(None);

/// [`KEEPER_ENV`] as the jailer started. Upstream's jailer clears its whole
/// environment first thing (`sanitize_process`), so the value is read before
/// `main`, by a C runtime initializer ([`READ_KEEPER_ENV`]). Unset only if
/// the initializer did not run, which [`new_pid_ns`] refuses: a keeper that
/// could not tell it is one would hand over again, without end.
static KEEPER_AT_START: std::sync::OnceLock<Option<std::ffi::OsString>> = std::sync::OnceLock::new();

extern "C" fn read_keeper_env() {
    let _ = KEEPER_AT_START.set(std::env::var_os(KEEPER_ENV));
}

/// Runs [`read_keeper_env`] with the C runtime's initializers, before `main`.
#[used]
#[unsafe(link_section = ".CRT$XCU")]
static READ_KEEPER_ENV: extern "C" fn() = read_keeper_env;

/// `--new-pid-ns`. In its own PID namespace the jailed Firecracker sees and
/// signals no other process; every Windows jail already holds that (module
/// documentation; `tools/windows/jailer-test.ps1` `pidns`): its token opens
/// no other process or thread, a process snapshot shows it none, and it has
/// a console of its own (`console`). What the flag changes is the jailer:
/// upstream clones Firecracker into the namespace, writes its pid to the
/// pid file and exits 0 at once, while Firecracker runs on. Windows has no
/// fork, so the jailer relaunches itself, the keeper, with the same
/// arguments, console and standard handles and an event, and waits: the
/// keeper builds the jail and runs Firecracker as without the flag, owning
/// the Job Object and the jail's drive for Firecracker's life, and sets the
/// event once Firecracker runs and its pid is in the pid file; the jailer
/// then exits 0, or with the keeper's status if the keeper ended first (the
/// jail could not be built, as upstream's jailer fails before it clones).
///
/// Called before the jail is built (`env::run`), where the jailer hands
/// over and exits and the keeper goes on, and where upstream clones, where
/// the keeper has nothing more to do.
pub fn new_pid_ns() -> Result<(), JailerError> {
    let mut keeper = KEEPER_EVENT.lock().unwrap();
    if keeper.is_some() {
        return Ok(());
    }
    let at_start = KEEPER_AT_START.get().ok_or_else(|| {
        HostError::Spawn("new-pid-ns", io::Error::other(format!("{KEEPER_ENV} was not read at start")))
    })?;
    if let Some(event) = keeper_event(at_start.as_deref())? {
        *keeper = Some(event);
        return Ok(());
    }
    drop(keeper);
    match hand_over_to_keeper() {
        Ok(never) => match never {},
        Err(err) => Err(HostError::Spawn("new-pid-ns", err).into()),
    }
}

/// The keeper's event from [`KEEPER_ENV`]'s value: `None` for a jailer that
/// is no keeper, an error for a value that is no handle value.
fn keeper_event(value: Option<&OsStr>) -> Result<Option<usize>, HostError> {
    let Some(value) = value else { return Ok(None) };
    match value.to_str().and_then(|v| v.parse().ok()) {
        Some(event) => Ok(Some(event)),
        None => Err(HostError::Spawn(
            "new-pid-ns",
            io::Error::other(format!("{KEEPER_ENV} is not a handle value: {}", value.to_string_lossy())),
        )),
    }
}

/// `--new-pid-ns`: starts the keeper ([`new_pid_ns`]) and exits as
/// upstream's jailer does once Firecracker runs in its namespace.
fn hand_over_to_keeper() -> io::Result<std::convert::Infallible> {
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForMultipleObjects};

    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: an unnamed, inheritable, manual-reset event.
    let event = unsafe { CreateEventW(&sa, 1, 0, std::ptr::null()) };
    if event.is_null() {
        return Err(last_error());
    }
    // SAFETY: a handle we own.
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    let mut argv = vec![std::env::current_exe()?.to_string_lossy().into_owned()];
    argv.extend(std::env::args().skip(1));
    // SAFETY: the jailer is single-threaded until the jail is built.
    unsafe { std::env::set_var(KEEPER_ENV, (event.as_raw_handle() as usize).to_string()) };
    // SAFETY: plain calls.
    let std_handles = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE].map(|w| unsafe { GetStdHandle(w) });
    let freezer = freezer_handover()?;
    let inherit: Vec<HANDLE> =
        std::iter::once(event.as_raw_handle()).chain(freezer.iter().map(AsRawHandle::as_raw_handle)).collect();
    let keeper = spawn_jailer(&argv, std_handles, &inherit, 0)?;
    let both = [event.as_raw_handle(), keeper.as_raw_handle()];
    // SAFETY: two handles we own.
    match unsafe { WaitForMultipleObjects(2, both.as_ptr(), 0, INFINITE) } {
        // Firecracker runs, its pid in the pid file.
        WAIT_OBJECT_0 => std::process::exit(0),
        r if r == WAIT_OBJECT_0 + 1 => {
            let mut code = 1u32;
            // SAFETY: the keeper, ended.
            unsafe { GetExitCodeProcess(keeper.as_raw_handle(), &mut code) };
            std::process::exit(code.cast_signed())
        }
        _ => Err(last_error()),
    }
}

/// Starts this jailer's binary with `argv`, standard handles `std` and no
/// other handle than those and `inherit` (each made inheritable), with
/// `flags`. Returns the process.
fn spawn_jailer(argv: &[String], std: [HANDLE; 3], inherit: &[HANDLE], flags: u32) -> io::Result<OwnedHandle> {
    use windows_sys::Win32::System::Threading::CreateProcessW;

    let mut cmd = wide(command_line(argv));
    let mut handles: Vec<HANDLE> = Vec::new();
    for h in std.iter().chain(inherit) {
        if !h.is_null() && *h != INVALID_HANDLE_VALUE && !handles.contains(h) {
            // SAFETY: a handle of ours.
            if unsafe { SetHandleInformation(*h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
                return Err(last_error());
            }
            handles.push(*h);
        }
    }
    // SAFETY: plain data.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap();
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    [si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError] = std;
    let mut size = 0usize;
    // SAFETY: a size query.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    let mut attrs = vec![0u64; size.div_ceil(8)];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = attrs.as_mut_ptr().cast();
    // SAFETY: a buffer of the size asked for.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        return Err(last_error());
    }
    if !handles.is_empty()
        // SAFETY: the handle array outlives the process creation.
        && unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles.as_slice()),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
    {
        // SAFETY: initialised above.
        unsafe { DeleteProcThreadAttributeList(list) };
        return Err(last_error());
    }
    si.lpAttributeList = list;
    // SAFETY: plain data.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated command line; the attribute list and handles
    // outlive the call.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            i32::from(!handles.is_empty()),
            flags | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null(),
            std::ptr::null(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    // SAFETY: initialised above.
    unsafe { DeleteProcThreadAttributeList(list) };
    if ok == 0 {
        return Err(last_error());
    }
    // SAFETY: handles CreateProcess gave us; the thread's is not needed.
    unsafe { windows_sys::Win32::Foundation::CloseHandle(pi.hThread) };
    // SAFETY: as above.
    Ok(unsafe { OwnedHandle::from_raw_handle(pi.hProcess) })
}

/// `--daemonize`: upstream double-forks, so the jailer returns 0 at once and
/// Firecracker keeps running with no controlling terminal, its stdio on
/// `/dev/null`. Windows has no fork; the jailer relaunches itself, detached
/// and without `--daemonize`, and exits 0. The relaunched jailer has no
/// console (`DETACHED_PROCESS`) and `NUL` for its standard handles, which it
/// passes on to Firecracker, so closing the terminal does not reach either;
/// it then owns the Job Object and the jail's drive for Firecracker's life
/// and waits for it, as a foreground jailer does. Called before any jail is
/// set up (`env::run`), so the detached jailer builds the whole jail itself.
///
/// Returns only on failure; on success it never returns (it exits 0).
pub fn daemonize() -> Result<(), JailerError> {
    match relaunch_detached() {
        Ok(never) => match never {},
        Err(err) => Err(HostError::Spawn("daemonize", err).into()),
    }
}

/// The `NUL` device, opened for a detached process's standard handle.
fn open_nul() -> io::Result<OwnedHandle> {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    let sa = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: a NUL-terminated device name; the handle is owned below.
    let h = unsafe {
        CreateFileW(
            wide("NUL").as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    // SAFETY: a handle we own.
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

/// Starts this jailer again with the same arguments but `--daemonize`,
/// detached: no console, `NUL` for the standard handles, only those inherited.
fn relaunch_detached() -> io::Result<std::convert::Infallible> {
    use windows_sys::Win32::System::Threading::DETACHED_PROCESS;

    // The same command line without --daemonize: the relaunched jailer runs
    // the foreground path.
    let mut argv = vec![std::env::current_exe()?.to_string_lossy().into_owned()];
    argv.extend(std::env::args().skip(1).filter(|a| a != "--daemonize"));
    let nul = open_nul()?;
    let nul = nul.as_raw_handle();
    let freezer = freezer_handover()?;
    let inherit: Vec<HANDLE> = freezer.iter().map(AsRawHandle::as_raw_handle).collect();
    // The detached jailer runs on; its handle is not needed.
    drop(spawn_jailer(&argv, [nul; 3], &inherit, DETACHED_PROCESS)?);
    std::process::exit(0);
}

/// The device nodes upstream creates in the jail. None is needed on Windows;
/// any other device is refused.
pub fn mknod_and_own_dev(dev_path: &CStr) -> Result<(), JailerError> {
    match dev_path.to_bytes() {
        // The Windows Hypervisor Platform is a system DLL, not a device.
        b"/dev/kvm"
        // The network endpoint is an AF_UNIX socket in the jail.
        | b"/dev/net/tun"
        // Random bytes come from the system's RNG (ProcessPrng).
        | b"/dev/urandom"
        // wick's userfaultfd is a socket protocol (crates/compat/userfaultfd).
        | b"/dev/userfaultfd" => Ok(()),
        other => {
            Err(HostError::UnsupportedDevice(String::from_utf8_lossy(other).into_owned()).into())
        }
    }
}

/// Upstream copies sysfs's MIDR_EL1 file into the jail (aarch64 only);
/// Windows has no sysfs.
#[allow(dead_code)]
pub fn copy_midr_el1_info() -> Result<(), JailerError> {
    Ok(())
}

/// `close_range(3, ~0)`: Windows handles are not inherited unless marked
/// inheritable, and the jailer passes Firecracker the standard handles only
/// (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), so there is nothing to close.
pub fn close_fds_by_close_range() -> Result<(), JailerError> {
    Ok(())
}

/// A jailed folder (`/dev`, `/run`, ...): created; its access is the jail
/// directory's, inherited.
pub fn setup_jailed_folder(folder: &Path) -> Result<(), JailerError> {
    std::fs::create_dir_all(folder).map_err(|err| JailerError::CreateDir(folder.to_owned(), err))
}

/// Why [`open_own`] refused a file.
#[derive(Debug)]
enum NotOwn {
    /// The open failed, or found a reparse point or a directory, where
    /// upstream's open (O_NOFOLLOW) fails: ELOOP, EISDIR.
    Open(io::Error),
    /// The file's information could not be read.
    Metadata(io::Error),
    /// The file has other names (a hard link).
    HardLink,
}

impl From<NotOwn> for io::Error {
    fn from(e: NotOwn) -> Self {
        match e {
            NotOwn::Open(e) | NotOwn::Metadata(e) => e,
            NotOwn::HardLink => io::Error::other("the file has other names (a hard link)"),
        }
    }
}

/// Opens `path` in the jail for writing, never through a link planted there,
/// as upstream opens what it writes in the jail: without following a symbolic
/// link (O_NOFOLLOW; here any reparse point, a junction too), refusing a file
/// with other names (a hard link). The checks are made on the handle returned,
/// so nothing can be swapped in between, and it is shared with no one. The
/// open creates the file or opens the one there in one step (OPEN_ALWAYS);
/// an existing file is emptied only after the checks.
fn open_own(path: &Path) -> Result<std::fs::File, NotOwn> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Foundation::{ERROR_STOPPED_ON_SYMLINK, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, GetFileInformationByHandle,
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .access_mode(GENERIC_WRITE | FILE_READ_ATTRIBUTES)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(NotOwn::Open)?;
    // SAFETY: zeroed is a valid value of the plain structure.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: an open handle and a structure to fill.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(NotOwn::Metadata(last_error()));
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(NotOwn::Open(io::Error::from_raw_os_error(ERROR_STOPPED_ON_SYMLINK.cast_signed())));
    }
    if info.nNumberOfLinks > 1 {
        return Err(NotOwn::HardLink);
    }
    file.set_len(0).map_err(NotOwn::Open)?;
    Ok(file)
}

/// Copies the operator's binary into the jail, as upstream does: a copy, so
/// two Firecracker processes never share its memory; never through a link
/// planted there ([`open_own`]). Upstream copies over an existing file of the
/// name without emptying it (no O_TRUNC), leaving the end of a longer one;
/// here it is emptied first.
pub fn copy_exec(src: &Path, dst: &Path) -> Result<(), JailerError> {
    let mut from = std::fs::File::open(src).map_err(|err| JailerError::Open(src.to_owned(), err))?;
    let mut to = open_own(dst).map_err(|e| match e {
        NotOwn::Open(err) => JailerError::Open(dst.to_owned(), err),
        NotOwn::Metadata(err) => JailerError::Metadata(dst.to_owned(), err),
        NotOwn::HardLink => JailerError::HardLink(dst.to_owned()),
    })?;
    io::copy(&mut from, &mut to).map_err(|err| JailerError::Copy(src.to_owned(), dst.to_owned(), err))?;
    Ok(())
}

/// The jail's `no-file` limit ([`install_resource_limits`]).
static NO_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(NO_FILE_DEFAULT);

/// The `no-file` limit each process of the jail gets ([`NO_FILE_ENV`]).
fn no_file_limit() -> u64 {
    NO_FILE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Upstream's resource limits.
///
/// - `fsize=` is refused: Windows cannot limit the size of the files a
///   process writes.
/// - `no-file=`, upstream's 2048 when not given (`no_file` is `None`), is
///   given to each process of the jail in [`NO_FILE_ENV`], as Linux's
///   `setrlimit` holds across the exec: a number of handles of the process,
///   where Linux counts descriptors, with nothing added or taken (a value
///   below the handles a process starts with fails its first descriptor, as
///   upstream's `test_negative_no_file_limit` expects of 3). wick's POSIX
///   layer fails a call that would make descriptors past it with `EMFILE`
///   (crates/compat/libc, `wick_nofile`, which names what it does not
///   cover). Enforced inside the process, it is not a bound a compromised
///   Firecracker can be held to.
pub fn install_resource_limits(file_size: Option<u64>, no_file: Option<u64>) -> Result<(), JailerError> {
    if file_size.is_some() {
        return Err(HostError::UnsupportedLimit(
            "fsize",
            "Windows cannot limit the size of the files a process writes",
        )
        .into());
    }
    NO_FILE.store(no_file.unwrap_or(NO_FILE_DEFAULT), std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Sets the jail directory's access (full access for the restricted token,
/// inherited, the jail's mandatory label), maps a free drive letter to it and
/// makes its root the current directory. Upstream's absolute paths resolve
/// inside the jail from here on.
pub(crate) fn enter_jail(path: &Path) -> Result<(), JailerError> {
    let root = plain(path);
    let fail = |what, err| HostError::Jail(root.clone(), what, err);
    std::fs::create_dir_all(&root).map_err(|e| fail("create the directory", e))?;
    let user = user_sid().map_err(|e| fail("the user's SID", e))?;
    let shared = {
        // Setting the directory's DACL rewrites the inherited entries of
        // what is in it, files other jails hold included: under ACL_LOCK.
        let _one_at_a_time = SessionLock::take(ACL_LOCK);
        set_security(&root, &jail_dacl(&user), false)
            .map_err(|e| fail("grant the jail's SID", e))?;
        set_security(&root, JAIL_LABEL, true).map_err(|e| fail("set the jail's integrity label", e))?;
        share_with_jail(&root)
    };
    let drive = std::fs::create_dir_all(root.join(JAIL_TMP))
        .map_err(|e| JailerError::from(fail("create tmp", e)))
        .and_then(|()| map_drive(&root).map_err(JailerError::from))
        .inspect_err(|_| unshare(None, &shared))?;
    // A step that fails from here on ends the jailer through `exit`, which
    // runs this: the drive goes with it (a killed jailer's goes at the next
    // jailer's sweep).
    // SAFETY: registers a handler that only takes a lock and removes a mapping.
    unsafe { atexit(unmap_at_exit) };
    std::env::set_current_dir(format!("{drive}\\")).map_err(JailerError::ChdirNewRoot)?;
    let mut jail = JAIL.lock().unwrap();
    if jail.is_some() {
        return Err(fail("enter", io::Error::other("the jailer enters one jail")).into());
    }
    *jail = Some(Jail { root, drive, shared });
    Ok(())
}

/// Applies an SDDL DACL (`label`: false) or mandatory label to `path`.
fn set_security(path: &Path, sddl: &str, label: bool) -> io::Result<()> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string and an out-pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_error());
    }
    let (mut present, mut defaulted) = (0, 0);
    let mut acl: *mut ACL = std::ptr::null_mut();
    // SAFETY: the descriptor converted above; out-pointers.
    let ok = unsafe {
        if label {
            GetSecurityDescriptorSacl(sd, &mut present, &mut acl, &mut defaulted)
        } else {
            GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted)
        }
    };
    let result = if ok == 0 {
        Err(last_error())
    } else {
        let info = if label {
            LABEL_SECURITY_INFORMATION
        } else {
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
        };
        let (dacl, sacl): (*const ACL, *const ACL) =
            if label { (std::ptr::null(), acl) } else { (acl, std::ptr::null()) };
        // SAFETY: a NUL-terminated path; the ACL lives in `sd`.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                info,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                sacl,
            )
        };
        if rc == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(rc as i32)) }
    };
    // SAFETY: allocated by the conversion.
    unsafe { LocalFree(sd) };
    result
}

/// As [`set_security`], through an open handle of the object (`WRITE_DAC`
/// for a DACL, `WRITE_OWNER` for a label), to that object alone
/// (`SetKernelObjectSecurity`). By name, Windows also rewrites the inherited
/// entries of everything a directory holds, opening each directory under it
/// to list it; a running jail's network directory is held open without
/// `FILE_SHARE_DELETE` ([`jail_network`]), which an open to list must share
/// (the sharing rule, `IoCheckShareAccess`), and whether that walk shares it
/// is not documented.
fn set_security_of(handle: HANDLE, sddl: &str, label: bool) -> io::Result<()> {
    use windows_sys::Win32::Security::SetKernelObjectSecurity;
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string and an out-pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_error());
    }
    let info = if label { LABEL_SECURITY_INFORMATION } else { DACL_SECURITY_INFORMATION };
    // SAFETY: an open handle and the descriptor converted above, which
    // carries the DACL's control bits (`P`, protected) with it.
    let result = if unsafe { SetKernelObjectSecurity(handle, info, sd) } == 0 { Err(last_error()) } else { Ok(()) };
    // SAFETY: allocated by the conversion.
    unsafe { LocalFree(sd) };
    result
}

/// Holds one of the logon session's jailer mutexes while alive.
struct SessionLock(windows_sys::Win32::Foundation::HANDLE);

/// Choosing and defining a drive letter. Jailers that start together each
/// found the same letter free and defined it: `DefineDosDevice` stacks a
/// second definition rather than refusing it, so one jail's drive named the
/// other's directory and its Firecracker never appeared where it was
/// expected (measured: three of six jails started at once). The mutex is in
/// the logon session's namespace, the mappings' own.
const DRIVES_LOCK: &str = "Local\\wick-jailer-drives";

/// Changing the DACL of a file another jail may hold (see [`share_with_jail`]):
/// every change of a DACL reads it and writes it whole, and of two made at
/// once, one is lost. Operators that edit those files' DACLs while jails
/// start take it too (`tools/windows/integration/wick_windows.py`).
const ACL_LOCK: &str = "Local\\wick-jailer-acl";

impl SessionLock {
    fn take(name: &str) -> Option<SessionLock> {
        use windows_sys::Win32::System::Threading::{CreateMutexW, INFINITE, WaitForSingleObject};
        // SAFETY: a NUL-terminated name; the handle is closed by Drop.
        let h = unsafe { CreateMutexW(std::ptr::null(), 0, wide(name).as_ptr()) };
        if h.is_null() {
            return None;
        }
        // SAFETY: our mutex handle. WAIT_ABANDONED (a jailer that died
        // holding it) also gives us the mutex.
        unsafe { WaitForSingleObject(h, INFINITE) };
        Some(SessionLock(h))
    }
}

/// The regular files under `dir` that have other names as well (hard links),
/// which may be in other jails: what inheritance from `dir` grants them it
/// grants to their other names too, and a jail that propagates its own
/// directory's DACL to its name of the file replaces the inherited entries
/// (a file holds one set of them). Reparse points are not followed.
fn linked_files(dir: &Path) -> Vec<PathBuf> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_READ_ATTRIBUTES, GetFileInformationByHandle,
    };
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let Ok(t) = e.file_type() else { continue };
            if t.is_symlink() {
                continue;
            }
            if t.is_dir() {
                stack.push(e.path());
                continue;
            }
            let Ok(f) = std::fs::OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).open(e.path()) else {
                continue;
            };
            // SAFETY: zeroed is a valid value of the plain structure.
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: an open handle and a structure to fill.
            if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } != 0 && info.nNumberOfLinks > 1 {
                out.push(e.path());
            }
        }
    }
    out
}

/// Gives `sid` an entry of its own (not inherited) for full access to
/// `path` (`grant`), or takes the ones it has away, keeping the rest of the
/// DACL as it is: written through a handle, not by name, which would have
/// Windows recompute the inherited entries from the directory of the name
/// given (one jail's, for a file several jails hold).
fn explicit_access(path: &Path, sid: &str, grant: bool) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, REVOKE_ACCESS,
        SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        InitializeSecurityDescriptor, NO_INHERITANCE, SECURITY_DESCRIPTOR, SetKernelObjectSecurity,
        SetSecurityDescriptorDacl,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, READ_CONTROL, WRITE_DAC};
    let file = std::fs::OpenOptions::new().access_mode(READ_CONTROL | WRITE_DAC).open(path)?;
    let handle = file.as_raw_handle();
    let sid = Sid::new(sid).map_err(|_| io::Error::last_os_error())?;
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut old: *mut ACL = std::ptr::null_mut();
    // SAFETY: an open handle and out-pointers.
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS,
        grfAccessMode: if grant { GRANT_ACCESS } else { REVOKE_ACCESS },
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.0.cast(),
        },
    };
    let mut new: *mut ACL = std::ptr::null_mut();
    // SAFETY: one entry, the DACL read above (in `sd`) and an out-pointer.
    let rc = unsafe { SetEntriesInAclW(1, &entry, old, &mut new) };
    let result = if rc != 0 {
        Err(io::Error::from_raw_os_error(rc.cast_signed()))
    } else {
        // SAFETY: zeroed is a valid value of the plain structure, initialized next.
        let mut desc: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let p: PSECURITY_DESCRIPTOR = (&raw mut desc).cast();
        // SAFETY: an absolute descriptor over `desc` holding the ACL made
        // above, both alive through the call; an open handle.
        let ok = unsafe {
            InitializeSecurityDescriptor(p, 1) != 0
                && SetSecurityDescriptorDacl(p, 1, new, 0) != 0
                && SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION, p) != 0
        };
        let result = if ok { Ok(()) } else { Err(io::Error::last_os_error()) };
        // SAFETY: allocated by SetEntriesInAclW.
        unsafe { LocalFree(new.cast()) };
        result
    };
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    result
}

/// What the jail directory gives the files already in it, kept for those it
/// shares with other jails: the jail's SID is given an entry of its own on
/// each of them ([`linked_files`]), which another jail's propagation keeps,
/// as Linux's chown of a file linked into two jails holds for both (they
/// are the same uid there). Without it, a jail started from a configuration
/// file next to another one sharing its kernel and root file system had its
/// Firecracker refused them (access denied, measured with six jails started
/// at once). The entries go when Firecracker ends ([`unshare`]). Called under
/// [`ACL_LOCK`], with the directory's own DACL set.
fn share_with_jail(root: &Path) -> Vec<PathBuf> {
    let mine = vm_sid();
    linked_files(root).into_iter().filter(|f| explicit_access(f, mine, true).is_ok()).collect()
}

/// Takes the jail's own entries off the files [`share_with_jail`] gave them
/// and off those shared with other jails in `root` now: an operator that
/// links a file into a running jail grants it to the jail's SID the same
/// way (Linux's chown), and a file other jails hold would otherwise keep an
/// entry for every jail that ever ran, until its ACL is full (an ACL holds
/// 64 KiB; past it, Windows error 1340, measured).
fn unshare(root: Option<&Path>, files: &[PathBuf]) {
    let mut all = files.to_vec();
    if let Some(root) = root {
        all.extend(linked_files(root).into_iter().filter(|f| !files.contains(f)));
    }
    if all.is_empty() {
        return;
    }
    let _one_at_a_time = SessionLock::take(ACL_LOCK);
    for f in &all {
        let _ = explicit_access(f, vm_sid(), false);
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        // SAFETY: the mutex this jailer holds, and its handle.
        unsafe {
            windows_sys::Win32::System::Threading::ReleaseMutex(self.0);
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Maps the highest free drive letter to `root`.
fn map_drive(root: &Path) -> Result<String, HostError> {
    let _one_at_a_time = SessionLock::take(DRIVES_LOCK);
    sweep_drives(root);
    // SAFETY: plain call.
    let used = unsafe { GetLogicalDrives() };
    let target = wide(root);
    for letter in (b'D'..=b'Z').rev() {
        if used & (1 << (letter - b'A')) != 0 {
            continue;
        }
        let drive = format!("{}:", letter as char);
        // SAFETY: NUL-terminated device name and target.
        if unsafe { DefineDosDeviceW(0, wide(&drive).as_ptr(), target.as_ptr()) } != 0 {
            record_drive(&drive, root);
            return Ok(drive);
        }
    }
    Err(HostError::NoDriveLetter)
}

unsafe extern "C" {
    /// The C runtime's: `std::process::exit` and returning from `main` run
    /// the handlers.
    fn atexit(f: extern "C" fn()) -> i32;
}

extern "C" fn unmap_at_exit() {
    if let Ok(jail) = JAIL.try_lock() {
        if let Some(jail) = jail.as_ref() {
            unmap_drive(jail);
        }
    }
}

/// Removes the jail's drive mapping.
fn unmap_drive(jail: &Jail) {
    remove_drive(&jail.drive, &jail.root.to_string_lossy());
    unshare(Some(&jail.root), &jail.shared);
}

/// Removes the mapping of `drive` to `target` (only that definition) and its
/// record.
fn remove_drive(drive: &str, target: &str) {
    // The definition is stored as the NT path `\??\<target>`, which an exact
    // match compares raw: without DDD_RAW_TARGET_PATH nothing matched and the
    // mapping stayed.
    let raw = format!(r"\??\{target}");
    // SAFETY: NUL-terminated device name and target; removes our definition only.
    unsafe {
        DefineDosDeviceW(
            DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
            wide(drive).as_ptr(),
            wide(&raw).as_ptr(),
        )
    };
    if let Some(dir) = drives_dir(Path::new(target)) {
        let _ = std::fs::remove_file(dir.join(&drive[..1]));
    }
}

/// Where the jailer records the drives it mapped, in the chroot base
/// directory of the jail `root` (`<base>\<exec>\<id>\root`; upstream clears
/// the environment, so no profile directory is known): `DefineDosDevice`
/// mappings last as long as the logon session, so a jailer that was killed
/// (or failed after mapping) would leave its letter taken until sign-out.
/// Each record, named by the letter, holds the jailer's pid and start time
/// and the target; the next jailer of the base removes the mappings of
/// jailers that are gone.
fn drives_dir(root: &Path) -> Option<PathBuf> {
    let dir = root.ancestors().nth(3)?.join(".wick-drives");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// A process's start time, `None` if it is not running.
fn start_time(pid: u32) -> Option<u64> {
    // SAFETY: plain call; the handle is closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    // SAFETY: a handle we own.
    let h = unsafe { OwnedHandle::from_raw_handle(h) };
    let mut times = [FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 }; 4];
    let [created, exited, kernel, user] = &mut times;
    // SAFETY: four out-parameters.
    if unsafe { GetProcessTimes(h.as_raw_handle(), created, exited, kernel, user) } == 0 {
        return None;
    }
    let mut code = 0u32;
    // SAFETY: as above.
    if unsafe { GetExitCodeProcess(h.as_raw_handle(), &mut code) } == 0 || code != STILL_ACTIVE.cast_unsigned() {
        return None;
    }
    Some(u64::from(created.dwHighDateTime) << 32 | u64::from(created.dwLowDateTime))
}

fn record_drive(drive: &str, root: &Path) {
    let Some(dir) = drives_dir(root) else { return };
    let pid = std::process::id();
    let started = start_time(pid).unwrap_or(0);
    let _ = std::fs::write(dir.join(&drive[..1]), format!("{pid} {started}\n{}", root.display()));
}

/// Removes the recorded mappings of the base of `root` whose jailer is gone.
fn sweep_drives(root: &Path) {
    let Some(dir) = drives_dir(root) else { return };
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    for e in entries.flatten() {
        let letter = e.file_name().to_string_lossy().into_owned();
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        let Some((owner, target)) = text.split_once('\n') else { continue };
        let mut owner = owner.split(' ').map(|w| w.parse::<u64>().ok());
        let (Some(Some(pid)), Some(Some(started))) = (owner.next(), owner.next()) else { continue };
        let alive = u32::try_from(pid).ok().and_then(start_time) == Some(started);
        if !alive {
            remove_drive(&format!("{letter}:"), target);
        }
    }
}

/// A SID from its string form, freed with `LocalFree`.
struct Sid(PSID);

impl Sid {
    fn new(s: &str) -> Result<Sid, HostError> {
        let mut sid: PSID = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string and an out-pointer.
        if unsafe { ConvertStringSidToSidW(wide(s).as_ptr(), &mut sid) } == 0 {
            return Err(HostError::Spawn("ConvertStringSidToSid", last_error()));
        }
        Ok(Sid(sid))
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSidToSidW.
        unsafe { LocalFree(self.0) };
    }
}

/// The user's SID, as a string.
fn user_sid() -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: our own token.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a token handle we own.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let user = token_info(token.as_raw_handle(), TokenUser).map_err(io::Error::other)?;
    // SAFETY: the buffer holds a TOKEN_USER.
    sid_string(unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

/// `sid` as text (`S-1-...`).
fn sid_string(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid SID and an out-pointer.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a NUL-terminated string allocated by the conversion.
    let s = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        s
    };
    Ok(s)
}

/// A token information class, in a buffer of the size the token asks for.
fn token_info(token: HANDLE, class: i32) -> Result<Vec<u64>, HostError> {
    let mut len = 0u32;
    // SAFETY: a size query.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
    // A class of a fixed size (TokenElevationType, TokenLinkedToken) answers
    // a size query with ERROR_BAD_LENGTH (24), with the length it wants
    // (measured on Windows 11 26H2: every jail failed with it), and takes
    // no other length.
    // SAFETY: plain call.
    let err = unsafe { GetLastError() };
    if err != ERROR_INSUFFICIENT_BUFFER && err != ERROR_BAD_LENGTH {
        return Err(HostError::Spawn("GetTokenInformation", last_error()));
    }
    if len == 0 {
        return Err(HostError::Spawn("GetTokenInformation", last_error()));
    }
    // u64 words: the structures hold pointers.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: a buffer of at least `len` bytes.
    if unsafe { GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &mut len) } == 0 {
        return Err(HostError::Spawn("GetTokenInformation", last_error()));
    }
    Ok(buf)
}

/// The two tokens of the jailed process: the lockdown primary token and the
/// initial impersonation token for its main thread.
struct Tokens {
    primary: OwnedHandle,
    initial: OwnedHandle,
}

fn tokens() -> Result<Tokens, HostError> {
    let mut process: HANDLE = std::ptr::null_mut();
    // SAFETY: our own token.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut process) } == 0 {
        return Err(HostError::Spawn("OpenProcessToken", last_error()));
    }
    // SAFETY: a token handle we own.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let process_h = process.as_raw_handle();

    let groups = token_info(process_h, TokenGroups)?;
    // SAFETY: the buffer holds a TOKEN_GROUPS.
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    // SAFETY: `GroupCount` entries follow.
    let entries = unsafe {
        std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
    };
    let logon = entries
        .iter()
        .find(|g| g.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
        .map(|g| g.Sid)
        .ok_or_else(|| HostError::Spawn("the logon SID", io::Error::other("no logon SID")))?;
    let user = token_info(process_h, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER.
    let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let sids: Vec<Sid> = RESTRICTING_SIDS
        .iter()
        .copied()
        .chain(Some(vm_sid()))
        .map(Sid::new)
        .collect::<Result<_, _>>()?;
    let mut restricting: Vec<SID_AND_ATTRIBUTES> =
        sids.iter().map(|s| SID_AND_ATTRIBUTES { Sid: s.0, Attributes: 0 }).collect();
    // The lockdown token without the logon SID, which would open the user's
    // processes for termination (module documentation); the initial token,
    // for start-up only, with it and the user's SID.
    let primary = restricted(process_h, &restricting)?;
    restricting.push(SID_AND_ATTRIBUTES { Sid: logon, Attributes: 0 });
    restricting.push(SID_AND_ATTRIBUTES { Sid: user_sid, Attributes: 0 });
    let initial = restricted(process_h, &restricting)?;
    let mut imp: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a token we own as an impersonation token.
    if unsafe {
        DuplicateTokenEx(
            initial.as_raw_handle(),
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut imp,
        )
    } == 0
    {
        return Err(HostError::Spawn("DuplicateTokenEx", last_error()));
    }
    // SAFETY: a token handle we own.
    let initial = unsafe { OwnedHandle::from_raw_handle(imp) };
    Ok(Tokens { primary, initial })
}

/// The privileges a jailed process keeps, when the operator's token holds
/// them: `SeChangeNotifyPrivilege` (traversal, the one `DISABLE_MAX_PRIVILEGE`
/// keeps) and nothing else; every other privilege is deleted from the jail's
/// tokens. "Lock pages in memory" (`SeLockMemoryPrivilege`, large pages) is
/// not kept either: a token below medium integrity cannot have a privilege
/// enabled (setting the level disables it, and enabling it again reports
/// success and leaves it disabled; measured on Windows 11 26H2 at
/// `S-1-16-6144` and `4096`, where `8192` and up keep it), so a jailed
/// Firecracker maps no large pages itself: the jailer makes them for it
/// (docs/PORTING.md row 10).
const KEPT_PRIVILEGES: [&str; 1] = ["SeChangeNotifyPrivilege"];

/// The privileges in `token`: (name, LUID and attributes).
fn privileges(token: HANDLE) -> Result<Vec<(String, LUID_AND_ATTRIBUTES)>, HostError> {
    let buf = token_info(token, TokenPrivileges)?;
    // SAFETY: the buffer holds a TOKEN_PRIVILEGES.
    let tp = unsafe { &*buf.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    // SAFETY: `PrivilegeCount` entries follow.
    let entries = unsafe { std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize) };
    entries
        .iter()
        .map(|p| {
            let mut name = [0u16; 64];
            let mut len = 64u32;
            // SAFETY: a LUID and a buffer of `len` characters.
            if unsafe { LookupPrivilegeNameW(std::ptr::null(), &p.Luid, name.as_mut_ptr(), &mut len) } == 0 {
                return Err(HostError::Spawn("LookupPrivilegeNameW", last_error()));
            }
            Ok((String::from_utf16_lossy(&name[..len as usize]), *p))
        })
        .collect()
}

/// `SE_GROUP_USE_FOR_DENY_ONLY` (winnt.h).
const GROUP_DENY_ONLY: u32 = 0x10;

/// The entries of a `TokenGroups` buffer.
fn group_entries(buf: &[u64]) -> &[SID_AND_ATTRIBUTES] {
    // SAFETY: the buffer holds a TOKEN_GROUPS with `GroupCount` entries.
    unsafe {
        let g = &*buf.as_ptr().cast::<TOKEN_GROUPS>();
        std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize)
    }
}

/// The groups of `from` (its `entries`) to mark deny-only in the jail's
/// token: for an elevated token, exactly the groups its UAC-filtered twin
/// (`TokenLinkedToken`) marks so; for a token UAC did not split, the groups
/// UAC's filter marks, by name ([`is_admin_group`]).
fn groups_to_deny(from: HANDLE, entries: &[SID_AND_ATTRIBUTES]) -> Result<Vec<SID_AND_ATTRIBUTES>, HostError> {
    let elevation = token_info(from, TokenElevationType)?;
    // SAFETY: the buffer holds a TOKEN_ELEVATION_TYPE.
    let kind = unsafe { *elevation.as_ptr().cast::<TOKEN_ELEVATION_TYPE>() };
    let names: Vec<String> = entries
        .iter()
        .map(|g| sid_string(g.Sid).map_err(|e| HostError::Spawn("a group's SID", e)))
        .collect::<Result<_, _>>()?;
    let denied: Vec<bool> = if kind == TokenElevationTypeFull {
        let linked = token_info(from, TokenLinkedToken)?;
        // SAFETY: the buffer holds a TOKEN_LINKED_TOKEN, whose handle is ours to close.
        let linked = unsafe { OwnedHandle::from_raw_handle((*linked.as_ptr().cast::<TOKEN_LINKED_TOKEN>()).LinkedToken) };
        let groups = token_info(linked.as_raw_handle(), TokenGroups)?;
        let mut by_uac = Vec::new();
        for g in group_entries(&groups) {
            if g.Attributes & GROUP_DENY_ONLY != 0 {
                by_uac.push(sid_string(g.Sid).map_err(|e| HostError::Spawn("a group's SID", e))?);
            }
        }
        names.iter().map(|n| by_uac.contains(n)).collect()
    } else {
        names.iter().map(|n| is_admin_group(n)).collect()
    };
    Ok(entries
        .iter()
        .zip(denied)
        .filter(|(g, d)| *d && g.Attributes & GROUP_DENY_ONLY == 0)
        .map(|(g, _)| SID_AND_ATTRIBUTES { Sid: g.Sid, Attributes: 0 })
        .collect())
}

/// Whether `sid` is a group a UAC-filtered token marks deny-only (what
/// `LUA_TOKEN` does): the administrators and the other operator groups,
/// local and domain, and "local account and member of Administrators".
fn is_admin_group(sid: &str) -> bool {
    const BUILTIN: [&str; 11] = ["544", "547", "548", "549", "550", "551", "553", "554", "556", "569", "578"];
    const DOMAIN: [&str; 8] = ["498", "512", "516", "517", "518", "519", "520", "521"];
    if sid == "S-1-5-114" {
        return true;
    }
    if let Some(rid) = sid.strip_prefix("S-1-5-32-") {
        return BUILTIN.contains(&rid);
    }
    sid.starts_with("S-1-5-21-") && sid.rsplit('-').next().is_some_and(|rid| DOMAIN.contains(&rid))
}

/// A restricted token: the administrators' groups deny-only
/// ([`groups_to_deny`]), the user its owner, no privileges but
/// [`KEPT_PRIVILEGES`], `restricting` SIDs, the default DACL and the jail's
/// integrity level. Not `LUA_TOKEN`, which does the first two but also
/// strips every privilege but a standard user's from an elevated token,
/// and whose list of groups is the system's to change.
fn restricted(from: HANDLE, restricting: &[SID_AND_ATTRIBUTES]) -> Result<OwnedHandle, HostError> {
    let held = privileges(from)?;
    let delete: Vec<LUID_AND_ATTRIBUTES> =
        held.iter().filter(|(n, _)| !KEPT_PRIVILEGES.contains(&n.as_str())).map(|(_, p)| *p).collect();
    let groups = token_info(from, TokenGroups)?;
    let disable = groups_to_deny(from, group_entries(&groups))?;
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: a token we own, valid SID arrays and a valid privilege array.
    if unsafe {
        CreateRestrictedToken(
            from,
            0,
            u32::try_from(disable.len()).unwrap(),
            disable.as_ptr(),
            u32::try_from(delete.len()).unwrap(),
            delete.as_ptr(),
            u32::try_from(restricting.len()).unwrap(),
            restricting.as_ptr(),
            &mut t,
        )
    } == 0
    {
        return Err(HostError::Spawn("CreateRestrictedToken", last_error()));
    }
    // SAFETY: a token handle we own.
    let t = unsafe { OwnedHandle::from_raw_handle(t) };
    // The user owns what the jail makes (an elevated token's owner is the
    // administrators' group, deny-only now).
    let user = token_info(from, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER.
    let owner = TOKEN_OWNER { Owner: unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid } };
    // SAFETY: a structure of the size passed; the SID lives in `user`.
    if unsafe {
        SetTokenInformation(
            t.as_raw_handle(),
            TokenOwner,
            (&raw const owner).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_OWNER>()).unwrap(),
        )
    } == 0
    {
        return Err(HostError::Spawn("TokenOwner", last_error()));
    }

    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string and an out-pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(&default_dacl()).as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(HostError::Spawn("the default DACL", last_error()));
    }
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: the descriptor converted above.
    unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) };
    let info = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
    // SAFETY: a structure of the size passed; the ACL lives in `sd`.
    let ok = unsafe {
        SetTokenInformation(
            t.as_raw_handle(),
            TokenDefaultDacl,
            (&raw const info).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_DEFAULT_DACL>()).unwrap(),
        )
    };
    // SAFETY: allocated by the conversion.
    unsafe { LocalFree(sd) };
    if ok == 0 {
        return Err(HostError::Spawn("TokenDefaultDacl", last_error()));
    }

    let low = Sid::new(JAIL_INTEGRITY_SID)?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES { Sid: low.0, Attributes: SE_GROUP_INTEGRITY },
    };
    // SAFETY: the label structure and the SID it points to.
    let size = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + unsafe { GetLengthSid(low.0) };
    // SAFETY: as above.
    if unsafe { SetTokenInformation(t.as_raw_handle(), TokenIntegrityLevel, (&raw const label).cast(), size) } == 0 {
        return Err(HostError::Spawn("TokenIntegrityLevel", last_error()));
    }
    Ok(t)
}

/// `GROUP_AFFINITY` (winnt.h).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct GroupAffinity {
    mask: usize,
    group: u16,
    reserved: [u16; 3],
}

/// The UI limits of a jail's job: every one a Job Object has
/// (`JOBOBJECT_BASIC_UI_RESTRICTIONS`). Microsoft Learn says a job that sets
/// any is not nested in another job nor another in it ("Nested Jobs",
/// `AssignProcessToJobObject`); Windows Server 2025 (build 26100) nests it
/// both ways all the same (`test_a_jails_job_under_a_parent_job_on_record`,
/// `test_nested_jobs_on_record`, CI run 43359525691). Older builds are not
/// measured.
const JAIL_UI_LIMITS: u32 = JOB_OBJECT_UILIMIT_DESKTOP
    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
    | JOB_OBJECT_UILIMIT_EXITWINDOWS
    | JOB_OBJECT_UILIMIT_GLOBALATOMS
    | JOB_OBJECT_UILIMIT_HANDLES
    | JOB_OBJECT_UILIMIT_READCLIPBOARD
    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

/// A Job Object with the cgroup limits: Firecracker dies with the jailer
/// (kill on close) and has no UI access.
fn job(limits: &Limits) -> Result<OwnedHandle, HostError> {
    // SAFETY: an unnamed job.
    let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if h.is_null() {
        return Err(HostError::Spawn("CreateJobObject", last_error()));
    }
    // SAFETY: a handle we own.
    limit_job(unsafe { OwnedHandle::from_raw_handle(h) }, limits)
}

/// Gives a job made just now what a jail's job has: the cgroup limits,
/// kill on close and no UI access. A jail under a parent cgroup has a job
/// with a name (`parent::Parent::jail_job`), any other the one of [`job`].
fn limit_job(job: OwnedHandle, limits: &Limits) -> Result<OwnedHandle, HostError> {
    // SAFETY: plain data.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    let basic = &mut info.BasicLimitInformation;
    basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if let Some(bytes) = limits.memory_bytes {
        basic.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.JobMemoryLimit = usize::try_from(bytes).unwrap_or(usize::MAX);
    }
    // cpuset.cpus: processors of the first group are the job's affinity;
    // any other group needs the per-group form (`JobObjectGroupInformationEx`).
    let groups: Vec<GroupAffinity> = limits
        .cpus
        .iter()
        .flatten()
        .map(|&(group, mask)| GroupAffinity { mask: usize::try_from(mask).unwrap_or(usize::MAX), group, reserved: [0; 3] })
        .collect();
    if let [only] = groups.as_slice() {
        if only.group == 0 {
            basic.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY;
            basic.Affinity = only.mask;
        }
    }
    // SAFETY: plain data.
    let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
    if let Some(rate) = limits.cpu_rate {
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu.Anonymous.CpuRate = rate;
    } else if let Some(weight) = limits.cpu_weight {
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
        cpu.Anonymous.Weight = weight;
    }
    let set = |class, ptr: *const std::ffi::c_void, size: usize, what| {
        // SAFETY: a structure of the size passed, for this class.
        if unsafe { SetInformationJobObject(job.as_raw_handle(), class, ptr, u32::try_from(size).unwrap()) } == 0 {
            Err(HostError::Spawn(what, last_error()))
        } else {
            Ok(())
        }
    };
    set(
        JobObjectExtendedLimitInformation,
        (&raw const info).cast(),
        std::mem::size_of_val(&info),
        "the job's limits",
    )?;
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS { UIRestrictionsClass: JAIL_UI_LIMITS };
    set(
        JobObjectBasicUIRestrictions,
        (&raw const ui).cast(),
        std::mem::size_of_val(&ui),
        "the job's UI restrictions",
    )?;
    if groups.len() > 1 || groups.first().is_some_and(|g| g.group != 0) {
        set(
            JobObjectGroupInformationEx,
            groups.as_ptr().cast(),
            std::mem::size_of_val(groups.as_slice()),
            "the job's processors",
        )?;
    }
    // The CPU rate hard cap or weight, before Firecracker runs: a cgroup's
    // limit holds from the exec on. A booting guest no longer needs to run
    // uncapped: it does not calibrate its local APIC timer, which WHP's
    // TSC-deadline mode (crates/compat/kvm-ioctls, `tscdeadline`) spares it
    // as KVM's does.
    if limits.cpu_rate.is_some() || limits.cpu_weight.is_some() {
        set(
            JobObjectCpuRateControlInformation,
            (&raw const cpu).cast(),
            std::mem::size_of_val(&cpu),
            "the job's CPU rate",
        )?;
    }
    Ok(job)
}

/// A command line from arguments, quoted as the MSVC runtime parses them.
fn command_line(args: &[String]) -> String {
    let mut line = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            line.push_str(arg);
            continue;
        }
        line.push('"');
        let mut backslashes = 0;
        for c in arg.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    line.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                    line.push('"');
                    backslashes = 0;
                }
                _ => {
                    line.extend(std::iter::repeat_n('\\', backslashes));
                    line.push(c);
                    backslashes = 0;
                }
            }
        }
        line.extend(std::iter::repeat_n('\\', backslashes * 2));
        line.push('"');
    }
    line
}

/// Upstream's arguments with `--start-time-cpu-us` set to 0. Upstream passes
/// the jailer's CPU time at the exec, which the exec'd Firecracker keeps
/// counting from (the same process); Firecracker reports its start-up CPU
/// time as its own CPU time minus that, plus `--parent-cpu-time-us`. Windows
/// starts a new process, whose CPU time starts at 0: the jailer's value
/// would make the difference negative (a panic in debug builds, a wrapped
/// metric in release ones). The jailer's share stays in
/// `--parent-cpu-time-us`.
fn cpu_start_of_new_process(args: &[String]) -> Vec<String> {
    let mut out = args.to_vec();
    if let Some(i) = out.iter().position(|a| a == "--start-time-cpu-us") {
        if let Some(value) = out.get_mut(i + 1) {
            *value = "0".to_owned();
        }
    }
    out
}

/// Checks that the binary in the jail takes the jail over.
fn check_handover(exe: &Path) -> Result<(), HostError> {
    let mut bytes = Vec::new();
    std::fs::File::open(exe)
        .and_then(|mut f| f.read_to_end(&mut bytes))
        .map_err(|e| HostError::Spawn("read the binary", e))?;
    if bytes.windows(HANDOVER_MARK.len()).any(|w| w == HANDOVER_MARK) {
        Ok(())
    } else {
        Err(HostError::NoHandover(exe.to_owned()))
    }
}

/// Upstream execs Firecracker as `uid:gid`; Windows has no exec. Starts the
/// copy of the binary in the jail suspended, on the lockdown token with the
/// initial token on its main thread, in a Job Object with the cgroup limits,
/// with the standard handles only, `WICK_JAIL`, the system root and the
/// jail's temporary directory as its environment, and the jail's root as its
/// current directory. Unless Firecracker runs with `--no-api`, starts the
/// API server's process the same way (the same binary, token, job and
/// standard handles: `vmm::ext::api_process`), with its end of a socket
/// pair and a `SYNCHRONIZE` handle to Firecracker inherited, and
/// Firecracker with the other end. Writes Firecracker's pid to the pid
/// file, waits for it, removes the jail's drive and exits with its status.
/// Returns only on failure.
pub fn exec_command(
    exec_file_path: &Path,
    chroot_dir: &Path,
    uid: u32,
    gid: u32,
    args: &[String],
) -> io::Error {
    match exec(exec_file_path, chroot_dir, uid, gid, args) {
        Ok(never) => match never {},
        Err(err) => io::Error::other(err),
    }
}

/// A process of the jail, started suspended ([`spawn_jailed`]).
struct Spawned {
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
}

/// Starts `exe` suspended as a process of the jail: on the lockdown token,
/// in the parent cgroup's job, if the jail has one, and in `job`
/// (`parent::enter`), with the initial token on its main thread, `vars` as its whole
/// environment, `std_handles` as its standard handles and `inherit` (which
/// holds them) as the only handles it inherits, and `cwd` as its current
/// directory. A step that fails after the creation ends the process.
#[allow(clippy::too_many_arguments)]
fn spawn_jailed(
    exe: &Path,
    cmd: &str,
    vars: &[String],
    std_handles: [HANDLE; 3],
    inherit: &[HANDLE],
    cwd: &str,
    tokens: &Tokens,
    parent: Option<&parent::Parent>,
    job: &OwnedHandle,
) -> Result<Spawned, HostError> {
    let mut cmd: Vec<u16> = wide(cmd);
    let mut env: Vec<u16> = Vec::new();
    for var in vars {
        env.extend(var.encode_utf16());
        env.push(0);
    }
    env.push(0);
    let mut size = 0usize;
    // SAFETY: a size query.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    let mut attrs = vec![0u64; size.div_ceil(8)];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = attrs.as_mut_ptr().cast();
    // SAFETY: a buffer of the size asked for.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        return Err(HostError::Spawn("InitializeProcThreadAttributeList", last_error()));
    }
    if !inherit.is_empty() {
        // SAFETY: the handle array outlives the process creation.
        if unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherit.as_ptr().cast(),
                std::mem::size_of_val(inherit),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err(HostError::Spawn("PROC_THREAD_ATTRIBUTE_HANDLE_LIST", last_error()));
        }
    }
    // SAFETY: plain data.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap();
    si.lpAttributeList = list;
    if !inherit.is_empty() {
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = std_handles[0];
        si.StartupInfo.hStdOutput = std_handles[1];
        si.StartupInfo.hStdError = std_handles[2];
    }
    // SAFETY: plain data.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let no_sa: *const SECURITY_ATTRIBUTES = std::ptr::null();
    // Firecracker has a console of its own, hidden: it is never attached to
    // the jailer's (`console`), and its console setup does not fail when the
    // jailer has none (daemonized).
    let create_flags = CREATE_SUSPENDED
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW;
    // SAFETY: NUL-terminated application path, command line, environment and
    // directory; the attribute list and tokens outlive the call.
    let created = unsafe {
        CreateProcessAsUserW(
            tokens.primary.as_raw_handle(),
            wide(exe).as_ptr(),
            cmd.as_mut_ptr(),
            no_sa,
            no_sa,
            i32::from(!inherit.is_empty()),
            create_flags,
            env.as_ptr().cast(),
            wide(cwd).as_ptr(),
            &si.StartupInfo,
            &mut pi,
        )
    };
    // SAFETY: initialised above.
    unsafe { DeleteProcThreadAttributeList(list) };
    if created == 0 {
        return Err(HostError::Spawn("CreateProcessAsUser", last_error()));
    }
    // SAFETY: handles CreateProcessAsUser gave us.
    let (process, thread) = unsafe {
        (OwnedHandle::from_raw_handle(pi.hProcess), OwnedHandle::from_raw_handle(pi.hThread))
    };
    let kill = |what, err| {
        // SAFETY: our suspended child.
        unsafe { TerminateProcess(process.as_raw_handle(), 1) };
        HostError::Spawn(what, err)
    };
    if let Err((step, err)) = parent::enter(parent, job, process.as_raw_handle()) {
        return Err(kill(step, err));
    }
    let mut thread_h = thread.as_raw_handle();
    // SAFETY: the child's main thread and the impersonation token.
    if unsafe { SetThreadToken(&mut thread_h, tokens.initial.as_raw_handle()) } == 0 {
        return Err(kill("SetThreadToken", last_error()));
    }
    Ok(Spawned { process, thread, pid: pi.dwProcessId })
}

fn exec(
    exec_file_path: &Path,
    chroot_dir: &Path,
    uid: u32,
    gid: u32,
    args: &[String],
) -> Result<std::convert::Infallible, HostError> {
    let jail = JAIL.lock().unwrap();
    let jail = jail
        .as_ref()
        .ok_or_else(|| HostError::Spawn("the jail", io::Error::other("the jailer did not enter one")))?;
    let name = exec_file_path.file_name().unwrap_or_default();
    let exe = jail.root.join(name);
    check_handover(&exe)?;
    // The API server is a process of its own (`vmm::ext::api_process`),
    // which the jailer makes alongside Firecracker.
    let api = !args.iter().any(|a| a == "--no-api");
    let limits = LIMITS.lock().unwrap().clone();

    // --netns: the jail's own directory of the network, named to
    // Firecracker, and no IP networking for the jail's binary, from before
    // it starts until the jailer ends (the filter's session is the jailer's).
    let netns = NETNS.lock().unwrap().take();
    let mut vars = Vec::new();
    // Both live until the jailer ends (it ends with `exit`, which drops
    // nothing): the filter session, and the jail's hold on its network.
    let (_net_filter, _jail_network) = match netns {
        Some((dir, mut filter)) => {
            let id = jail
                .root
                .parent()
                .and_then(Path::file_name)
                .ok_or_else(|| HostError::Netns(dir.clone(), format!("no jail id in {}", jail.root.display())))?;
            let network = jail_network(&dir, id)?;
            vars.push(format!("{NETNS_ENV}={}", network.dir.display()));
            filter.block(&exe).map_err(|e| HostError::Netns(dir.clone(), e.to_string()))?;
            (Some(filter), Some(network))
        }
        None => (None, None),
    };

    let drive_root = format!("{}\\", jail.drive);
    let mut argv = vec![format!("{drive_root}{}", name.to_string_lossy())];
    argv.extend(cpu_start_of_new_process(args));
    let cmd = command_line(&argv);
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let tmp = format!("{drive_root}{JAIL_TMP}");
    vars.extend([
        format!("{JAIL_ENV}={uid}:{gid}:{}", chroot_dir.display()),
        format!("{NO_FILE_ENV}={}", no_file_limit()),
        format!("SystemRoot={system_root}"),
        format!("TEMP={tmp}"),
        format!("TMP={tmp}"),
    ]);

    // The freezer (`freezer`): proven on this host first, as its job
    // information class is not documented; then the jail's files, in the
    // directory that holds `root`.
    freezer::self_check().map_err(HostError::Freezer)?;
    let mut freezer = freezer::Freezer::for_exec(jail.root.parent().unwrap_or(jail.root.as_path())).map_err(HostError::Freezer)?;

    let tokens = tokens()?;
    // The parent cgroup, if the jail has one: held until the jailer ends,
    // with its jail, and the jail's job under it, with the limits as a job
    // there takes them, a name, and what it was asked for kept beside it.
    let parent = parent::for_jail()?;
    let (job, _asked) = match &parent {
        Some(parent) => {
            let (job, asked) = parent.jail_job(&limits)?;
            (job, Some(asked))
        }
        None => (job(&limits)?, None),
    };
    let mut job_freeze = freezer::Job(job.as_raw_handle());

    // The standard handles, inheritable, and only them; those that are the
    // jailer's console are pipes it relays (`console`).
    let mut terminal = console::Terminal::new().map_err(|e| HostError::Spawn("the terminal relay", e))?;
    let std_handles = terminal.handles();
    let mut handles: Vec<HANDLE> = Vec::new();
    for h in std_handles {
        if !h.is_null() && h != INVALID_HANDLE_VALUE && !handles.contains(&h) {
            // SAFETY: one of our standard handles.
            if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } != 0 {
                handles.push(h);
            }
        }
    }
    // The API server is a process of the jail too (`vmm::ext::api_process`):
    // the same binary, token, job and standard handles, made first, listening
    // for Firecracker on a socket inside the jail (a connection, so that each
    // end's peer is the other process, which passing handles over it needs:
    // the ends of a socket pair both name the process that made the pair).
    // Firecracker gets the path, and a handle to the API process to bound its
    // connecting with. The Job Object ends either when the jailer ends.
    let link_path = api.then(|| format!("{tmp}\\api-link"));
    let api_process = match &link_path {
        Some(path) => {
            let mut api_vars = vars.clone();
            api_vars.push(format!("{API_LINK_ENV}={path}"));
            Some(spawn_jailed(&exe, &cmd, &api_vars, std_handles, &handles, &drive_root, &tokens, parent.as_ref(), &job)?)
        }
        None => None,
    };
    let api_handle = api_process.as_ref().map(|p| p.process.as_raw_handle());
    let mut fc_vars = vars.clone();
    let mut fc_handles = handles.clone();
    // The console's mode follows Firecracker's requests (`console`): its
    // end of the mode pipe, to Firecracker only.
    if let Some(h) = terminal.mode_pipe() {
        fc_vars.push(format!("{}={}", console::MODE_ENV, h as usize));
        fc_handles.push(h);
    }
    let mut api_h: HANDLE = std::ptr::null_mut();
    if let (Some(path), Some(api)) = (&link_path, api_handle) {
        // SAFETY: duplicates a handle we own, for waiting on and for
        // duplicating handles into (the two may not open each other: both
        // run the jail's restricted token), inheritable.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                api,
                GetCurrentProcess(),
                &mut api_h,
                SYNCHRONIZE | PROCESS_DUP_HANDLE,
                1,
                0,
            )
        } == 0
        {
            let err = last_error();
            // SAFETY: our child, suspended still.
            unsafe { TerminateProcess(api, 1) };
            return Err(HostError::Spawn("a handle to the API process for Firecracker", err));
        }
        fc_vars.push(format!("{API_WAITING_ENV}={path}"));
        fc_vars.push(format!("{API_PROCESS_ENV}={}", api_h as usize));
        fc_handles.push(api_h);
    }
    // SAFETY: the handle just made, or null.
    let api_h = (!api_h.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(api_h) });
    // Large pages for guest memory: a jailed process cannot have "Lock pages
    // in memory" enabled, so the jailer, which holds it, makes the sections
    // (`large_pages`); without the privilege nothing is offered and
    // Firecracker refuses large pages naming the cause.
    let broker = large_pages::Broker::new(limits.large_page_bytes)
        .map_err(|e| HostError::Spawn("the large-page broker", e))?;
    if let Some(b) = &broker {
        fc_vars.push(format!("{}={}", large_pages::ENV, b.child_value()));
        fc_handles.extend(b.child_handles());
    }
    let fc = match spawn_jailed(&exe, &cmd, &fc_vars, std_handles, &fc_handles, &drive_root, &tokens, parent.as_ref(), &job) {
        Ok(fc) => fc,
        Err(err) => {
            if let Some(api) = api_handle {
                // SAFETY: our child, suspended still.
                unsafe { TerminateProcess(api, 1) };
            }
            return Err(err);
        }
    };
    // Firecracker has its own copy now.
    drop(api_h);
    let fc_process = fc.process.as_raw_handle();
    let kill = move |what, err| {
        // SAFETY: our children, whose handles are held to the end.
        unsafe {
            TerminateProcess(fc_process, 1);
            if let Some(api) = api_handle {
                TerminateProcess(api, 1);
            }
        }
        HostError::Spawn(what, err)
    };
    terminal.started();
    // Upstream's pid file holds the jailer's pid, which an exec keeps; here it
    // is Firecracker's.
    let pid_file = jail.root.join(format!("{}.pid", name.to_string_lossy()));
    if let Err(e) = open_own(&pid_file).map_err(io::Error::from).and_then(|mut f| write!(f, "{}", fc.pid)) {
        return Err(kill("the pid file", e));
    }
    // Frozen now if the file says so: a process resumed in a frozen job does
    // not run (measured, `freezer`).
    if let Err(f) = freezer.before_resume(&mut job_freeze) {
        freezer.killed(&f);
        return Err(kill("the jail's freezer", io::Error::other(f.to_string())));
    }
    for p in std::iter::once(&fc).chain(api_process.as_ref()) {
        // SAFETY: the suspended main thread.
        if unsafe { ResumeThread(p.thread.as_raw_handle()) } == u32::MAX {
            return Err(kill("ResumeThread", last_error()));
        }
    }
    let process = fc.process;
    drop(fc.thread);
    drop(api_process);
    let _broker = broker.map(|b| b.serve(process.as_raw_handle()));
    // --new-pid-ns: Firecracker runs and its pid is in the pid file; the
    // jailer that handed over to this keeper exits 0 (`new_pid_ns`).
    if let Some(event) = KEEPER_EVENT.lock().unwrap().take() {
        // SAFETY: the event this keeper inherited; set once, then closed.
        unsafe {
            SetEvent(event as HANDLE);
            windows_sys::Win32::Foundation::CloseHandle(event as HANDLE);
        }
    }
    // Firecracker's end, and meanwhile what the freezer's files ask for. A
    // request that cannot be carried out kills the jail.
    let [change, timer] = freezer.handles();
    let waits = [process.as_raw_handle(), change, timer];
    let mut killed = false;
    loop {
        // SAFETY: three handles we hold.
        let r = unsafe { WaitForMultipleObjects(3, waits.as_ptr(), 0, INFINITE) };
        let result = match r.wrapping_sub(WAIT_OBJECT_0) {
            0 => break,
            which @ (1 | 2) => freezer.woken(&mut job_freeze, usize::try_from(which - 1).unwrap()),
            _ => Err(freezer::Failure::Files("waiting for Firecracker", last_error())),
        };
        if let Err(f) = result {
            freezer.killed(&f);
            killed = true;
            // SAFETY: the jail's job; its processes end with exit code 1.
            unsafe {
                TerminateJobObject(job.as_raw_handle(), 1);
                WaitForSingleObject(process.as_raw_handle(), INFINITE);
            }
            break;
        }
    }
    // What is left of the jail ends with Firecracker, as without the
    // freezer: thawed, if it was frozen.
    if !killed
        && let Err(f) = freezer.firecracker_exited(&mut job_freeze)
    {
        freezer.killed(&f);
        // SAFETY: the jail's job.
        unsafe { TerminateJobObject(job.as_raw_handle(), 1) };
    }
    let mut code = 1u32;
    // SAFETY: our child, ended.
    unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) };
    terminal.finish();
    unmap_drive(jail);
    drop(job);
    // The jail is gone: its hold on the parent cgroup's job ends here.
    drop(parent);
    freezer.emptied();
    std::process::exit(code.cast_signed());
}

#[cfg(test)]
mod tests {
    use super::*;

    // --netns names a directory of endpoints, which must exist, as the
    // namespace file must on Linux.
    #[test]
    fn test_netns_needs_an_existing_directory() {
        let dir = std::env::temp_dir().join(format!("wick-jailer-netns-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(
            join_netns(dir.to_str().unwrap()).unwrap_err(),
            JailerError::Host(HostError::Netns(_, _))
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(matches!(
            join_netns(file.to_str().unwrap()).unwrap_err(),
            JailerError::Host(HostError::Netns(_, _))
        ));
        // An existing directory: the network is recorded, with a filter
        // session whose filters are not added yet; or, in a test process
        // that is not elevated, the refusal that names elevation.
        match join_netns(dir.to_str().unwrap()) {
            Ok(()) => {
                let (recorded, filter) = NETNS.lock().unwrap().take().unwrap();
                assert_eq!(recorded, plain(&std::fs::canonicalize(&dir).unwrap()));
                assert!(!filter.is_blocking());
            }
            Err(JailerError::Host(HostError::Netns(_, msg))) => assert!(msg.contains("elevated"), "{msg}"),
            Err(e) => panic!("{e}"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The mandatory label of `path` as SDDL (`S:...`).
    fn label_sddl(path: &Path) -> String {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        };
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated path and out-pointers.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                wide(path).as_ptr(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(rc, 0, "{path:?}");
        let mut text: *mut u16 = std::ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: the descriptor read above; out-pointers.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, LABEL_SECURITY_INFORMATION, &mut text, &mut len)
        };
        assert_ne!(ok, 0, "{path:?}");
        // SAFETY: `len` characters allocated by the conversion.
        let s = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(text, len as usize)) };
        // SAFETY: allocated by the calls above.
        unsafe {
            LocalFree(text.cast());
            LocalFree(sd);
        }
        s
    }

    /// Who reaches a network directory and every jail's directory in it
    /// besides that jail: SYSTEM, the administrators, the user and the
    /// network directory's owner `owner`, sorted.
    fn operators(owner: &str) -> Vec<String> {
        let mut sids = vec!["S-1-5-18".to_owned(), "S-1-5-32-544".to_owned(), user_sid().unwrap()];
        if !sids.iter().any(|s| s == owner) {
            sids.push(owner.to_owned());
        }
        sids.sort();
        sids
    }

    /// The SIDs of `path`'s DACL, sorted, which must all be its own (not
    /// inherited) full-access allow entries for files and directories.
    fn full_access_sids(path: &Path) -> Vec<String> {
        let full = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        let entries = dacl_entries(path).unwrap();
        let mut sids = Vec::new();
        for (k, f, m, s) in &entries {
            assert!(
                u32::from(*k) == ACCESS_ALLOWED_ACE_TYPE && u32::from(*f) == full && *m == FILE_ALL_ACCESS,
                "{path:?}: an entry other than its own full access: {entries:?}"
            );
            sids.push(s.clone());
        }
        sids.sort();
        sids
    }

    /// A fresh directory under the temporary directory.
    fn fresh_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wick-jailer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // A network directory grants no jail anything: each jail's endpoints are
    // in a directory of its own in it (test_each_jail_has_a_network_
    // directory_of_its_own), as a TAP is its owner's on Linux
    // (drivers/net/tun.c, tun_not_capable). The entry an earlier jailer gave
    // a jail on the directory itself goes, and so does what its parent
    // grants (Authenticated Users, which every jail's token holds).
    #[test]
    fn test_the_network_directory_grants_no_jail() {
        let net = fresh_dir("net");
        let user = user_sid().unwrap();
        let earlier = "S-1-9-1-2-3-4";
        set_security(&net, &format!("D:AI(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})(A;OICI;FA;;;{earlier})"), false).unwrap();
        let owner = owner_sid(&net).unwrap();
        let network = jail_network(&net, OsStr::new("a")).unwrap();
        let sddl = dacl_sddl(&net).unwrap();
        assert!(sddl.starts_with("D:P"), "not protected: {sddl}");
        assert_eq!(full_access_sids(&net), operators(&owner), "{sddl}");
        drop(network);
        std::fs::remove_dir_all(&net).unwrap();
    }

    // Each jail's endpoints are made in `<network>\<id>`, which only the jail
    // and the network's operators (SYSTEM, the administrators, the user, the
    // network directory's owner) reach, labelled with the jail's integrity
    // level so that the jail can make them. What a jail of the same id that
    // ended left there goes (its dead endpoints); the directory stays when
    // the jail ends, as upstream leaves the jail's root. A network path
    // whose endpoints could not be named within `sockaddr_un`'s 108 bytes is
    // refused before anything is made.
    #[test]
    fn test_each_jail_has_a_network_directory_of_its_own() {
        let net = fresh_dir("netdir");
        let own = net.join("a");
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(own.join("tap0"), b"").unwrap();
        let owner = owner_sid(&net).unwrap();
        let network = jail_network(&net, OsStr::new("a")).unwrap();
        assert_eq!(network.dir, own);
        let sddl = dacl_sddl(&own).unwrap();
        assert!(sddl.starts_with("D:P"), "not protected: {sddl}");
        let mut want = operators(&owner);
        want.push(vm_sid().to_owned());
        want.sort();
        assert_eq!(full_access_sids(&own), want, "{sddl}");
        let label = label_sddl(&own);
        assert!(label.contains(JAIL_INTEGRITY_SID), "{label}");
        assert!(!own.join("tap0").exists(), "the endpoint a dead jail of the id left is still there");
        drop(network);
        assert!(own.is_dir(), "the jail's network directory went with the jail");
        let long = "i".repeat(100);
        match jail_network(&net, OsStr::new(&long)) {
            Err(HostError::Netns(_, msg)) => assert!(msg.contains("too long"), "{msg}"),
            other => panic!("a network path too long for an endpoint: {other:?}"),
        }
        assert!(!net.join(&long).exists(), "a directory was made for a refused jail");
        std::fs::remove_dir_all(&net).unwrap();
    }

    // As a TAP a Firecracker has attached refuses a second attach (Linux:
    // tun_attach, EBUSY), a jail's network directory refuses a second jail of
    // the same id while the first holds it, and the first keeps its
    // endpoint; once it has ended, the id starts again.
    #[test]
    fn test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint() {
        let net = fresh_dir("netbusy");
        let first = jail_network(&net, OsStr::new("a")).unwrap();
        // The first jail's endpoint (a file standing for its socket).
        let endpoint = first.dir.join("tap0");
        std::fs::write(&endpoint, b"").unwrap();
        match jail_network(&net, OsStr::new("a")) {
            Err(HostError::Netns(_, msg)) => assert!(msg.contains("busy"), "{msg}"),
            other => panic!("a second jail of one id: {other:?}"),
        }
        assert!(endpoint.exists(), "the second jail of the id took the first one's endpoint");
        let other = jail_network(&net, OsStr::new("b")).unwrap();
        assert_ne!(other.dir, first.dir, "two jails share a network directory");
        drop(first);
        let again = jail_network(&net, OsStr::new("a")).unwrap();
        assert!(!endpoint.exists(), "the endpoint of the jail that ended is still there");
        drop((again, other));
        std::fs::remove_dir_all(&net).unwrap();
    }

    // The jail's token marks the administrators' groups deny-only and makes
    // the user its owner, as a UAC-filtered token does, without the LUA flag
    // that would strip SeLockMemoryPrivilege with the rest.
    #[test]
    fn test_tokens_disable_the_administrators_and_are_owned_by_the_user() {
        const DENY_ONLY: u32 = GROUP_DENY_ONLY;
        assert!(is_admin_group("S-1-5-32-544") && is_admin_group("S-1-5-114") && is_admin_group("S-1-5-21-1-2-3-512"));
        assert!(!is_admin_group("S-1-5-32-545") && !is_admin_group("S-1-5-21-1-2-3-1001") && !is_admin_group("S-1-1-0"));
        // On an elevated token, UAC's own filter (the linked token) and the
        // list agree on which of this token's groups to mark.
        let mut own: HANDLE = std::ptr::null_mut();
        // SAFETY: our own token.
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own) }, 0);
        // SAFETY: a token handle we own.
        let own = unsafe { OwnedHandle::from_raw_handle(own) };
        let groups = token_info(own.as_raw_handle(), TokenGroups).unwrap();
        let entries = group_entries(&groups);
        let elevation = token_info(own.as_raw_handle(), TokenElevationType).unwrap();
        // SAFETY: the buffer holds a TOKEN_ELEVATION_TYPE.
        if unsafe { *elevation.as_ptr().cast::<TOKEN_ELEVATION_TYPE>() } == TokenElevationTypeFull {
            let by_uac: Vec<String> =
                groups_to_deny(own.as_raw_handle(), entries).unwrap().iter().map(|g| sid_string(g.Sid).unwrap()).collect();
            let by_list: Vec<String> = entries
                .iter()
                .filter(|g| g.Attributes & DENY_ONLY == 0)
                .map(|g| sid_string(g.Sid).unwrap())
                .filter(|n| is_admin_group(n))
                .collect();
            assert_eq!(by_uac, by_list, "UAC's filter and the list disagree");
        } else {
            eprintln!("this token is not elevated: UAC's filter was not compared with the list");
        }
        let t = tokens().unwrap();
        let user = user_sid().unwrap();
        for token in [&t.primary, &t.initial] {
            let groups = token_info(token.as_raw_handle(), TokenGroups).unwrap();
            // SAFETY: the buffer holds a TOKEN_GROUPS with `GroupCount` entries.
            let entries = unsafe {
                let g = &*groups.as_ptr().cast::<TOKEN_GROUPS>();
                std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize)
            };
            let mut seen = 0;
            for g in entries {
                let sid = sid_string(g.Sid).unwrap();
                if is_admin_group(&sid) {
                    seen += 1;
                    assert_ne!(g.Attributes & DENY_ONLY, 0, "{sid} is not deny-only");
                }
            }
            if seen == 0 {
                eprintln!("this account is in no administrators' group: only the owner was checked");
            }
            let owner = token_info(token.as_raw_handle(), TokenOwner).unwrap();
            // SAFETY: the buffer holds a TOKEN_OWNER.
            let owner = sid_string(unsafe { (*owner.as_ptr().cast::<TOKEN_OWNER>()).Owner }).unwrap();
            assert_eq!(owner, user);
        }
    }

    // The keeper's variable is read before main, ahead of upstream's
    // clearing of the environment.
    #[test]
    fn test_keeper_env_is_read_before_main() {
        assert!(KEEPER_AT_START.get().is_some());
    }

    // --new-pid-ns: a jailer without the keeper's variable hands over; the
    // keeper takes its event from it; anything else is refused.
    #[test]
    fn test_keeper_event() {
        assert!(keeper_event(None).unwrap().is_none());
        assert_eq!(keeper_event(Some(OsStr::new("1234"))).unwrap(), Some(1234));
        for bad in ["", "x", "-1", "0x10"] {
            assert!(keeper_event(Some(OsStr::new(bad))).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn test_devices() {
        for dev in [c"/dev/kvm", c"/dev/net/tun", c"/dev/urandom", c"/dev/userfaultfd"] {
            mknod_and_own_dev(dev).unwrap();
        }
        assert!(matches!(
            mknod_and_own_dev(c"/dev/nitro_enclaves").unwrap_err(),
            JailerError::Host(HostError::UnsupportedDevice(_))
        ));
    }

    #[test]
    fn test_resource_limits() {
        assert!(matches!(
            install_resource_limits(Some(1 << 20), None).unwrap_err(),
            JailerError::Host(HostError::UnsupportedLimit("fsize", _))
        ));
        // no-file=: any value, below the handles a process starts with too
        // (upstream's test_negative_no_file_limit gives 3), as Linux's
        // setrlimit takes it.
        for n in [3, 512, 2048] {
            install_resource_limits(None, Some(n)).unwrap();
            assert_eq!(no_file_limit(), n);
        }
        // Without it: upstream's default.
        install_resource_limits(None, None).unwrap();
        assert_eq!(no_file_limit(), 2048);
        // Through upstream's argument parsing: given or not.
        let mut limits = crate::resource_limits::ResourceLimits::default();
        limits.set_no_file(512);
        limits.install().unwrap();
        assert_eq!(no_file_limit(), 512);
        crate::resource_limits::ResourceLimits::default().install().unwrap();
        assert_eq!(no_file_limit(), 2048);
        // The variable is the one the compat libc and wick-os read.
        assert_eq!(NO_FILE_ENV, "WICK_NO_FILE");
    }

    #[test]
    fn test_command_line() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(command_line(&args(&["a", "b c", ""])), r#"a "b c" """#);
        assert_eq!(command_line(&args(&[r#"x"y"#, r"d\ e\"])), r#""x\"y" "d\ e\\""#);
        assert_eq!(command_line(&args(&[r"C:\p\f.exe", "--id", "x"])), r"C:\p\f.exe --id x");
    }

    #[test]
    fn test_cpu_start_of_new_process() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            cpu_start_of_new_process(&args(&[
                "--id", "a", "--start-time-cpu-us", "123456", "--parent-cpu-time-us", "99", "--",
                "--start-time-cpu-us", "7",
            ])),
            args(&[
                "--id", "a", "--start-time-cpu-us", "0", "--parent-cpu-time-us", "99", "--",
                "--start-time-cpu-us", "7",
            ])
        );
        assert_eq!(cpu_start_of_new_process(&args(&["--id"])), args(&["--id"]));
    }

    #[test]
    fn test_plain() {
        assert_eq!(plain(Path::new(r"\\?\C:\j\root")), PathBuf::from(r"C:\j\root"));
        assert_eq!(plain(Path::new(r"C:\j")), PathBuf::from(r"C:\j"));
        assert_eq!(plain(Path::new(r"\\?\UNC\s\x")), PathBuf::from(r"\\?\UNC\s\x"));
    }

    #[test]
    fn test_handover_mark() {
        let dir = std::env::temp_dir().join(format!("wick-jailer-mark-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let without = dir.join("plain.exe");
        std::fs::write(&without, b"MZ no mark").unwrap();
        assert!(matches!(check_handover(&without).unwrap_err(), HostError::NoHandover(_)));
        let with = dir.join("marked.exe");
        let mut bytes = b"MZ ".to_vec();
        bytes.extend_from_slice(HANDOVER_MARK);
        std::fs::write(&with, bytes).unwrap();
        check_handover(&with).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_tokens_and_job() {
        // The lockdown and initial tokens can be made from a normal user's
        // token, and a job with every limit.
        tokens().unwrap();
        job(&Limits { memory_bytes: Some(256 << 20), cpu_rate: Some(5000), ..Limits::default() }).unwrap();
        job(&Limits { cpu_weight: Some(3), cpus: Some(vec![(0, 1)]), ..Limits::default() }).unwrap();
    }

    /// The jail's tokens hold no privilege but traversal, enabled
    /// (docs/PORTING.md, row 10): not "Lock pages in memory" either, which
    /// this process's token may hold; this process's token has others.
    #[test]
    fn test_tokens_keep_only_traversal() {
        let mut own: HANDLE = std::ptr::null_mut();
        // SAFETY: our own token.
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own) }, 0);
        // SAFETY: a token handle we own.
        let own = unsafe { OwnedHandle::from_raw_handle(own) };
        let mine: Vec<String> = privileges(own.as_raw_handle()).unwrap().into_iter().map(|(n, _)| n).collect();
        assert!(mine.iter().any(|n| !KEPT_PRIVILEGES.contains(&n.as_str())), "{mine:?}");
        let want = vec![("SeChangeNotifyPrivilege".to_string(), true)];
        let t = tokens().unwrap();
        for token in [&t.primary, &t.initial] {
            let kept: Vec<(String, bool)> = privileges(token.as_raw_handle())
                .unwrap()
                .into_iter()
                .map(|(n, p)| (n, p.Attributes & windows_sys::Win32::Security::SE_PRIVILEGE_ENABLED != 0))
                .collect();
            assert_eq!(kept, want, "the jail's token, from {mine:?}");
        }
        if !mine.iter().any(|n| n == "SeLockMemoryPrivilege") {
            eprintln!("this account lacks SeLockMemoryPrivilege: its removal from the jail was not exercised");
        }
    }

    /// The job's CPU rate, read back.
    fn cpu_rate_of(job: &OwnedHandle) -> JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        use windows_sys::Win32::System::JobObjects::QueryInformationJobObject;
        // SAFETY: plain data.
        let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: a structure of the size passed, for this class.
        let ok = unsafe {
            QueryInformationJobObject(
                job.as_raw_handle(),
                JobObjectCpuRateControlInformation,
                (&raw mut cpu).cast(),
                u32::try_from(std::mem::size_of_val(&cpu)).unwrap(),
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        cpu
    }

    /// The CPU rate hard cap is the job's before Firecracker is in it, as a
    /// cgroup's limit holds from the exec: no grace (docs/PORTING.md, row 9).
    #[test]
    fn test_cpu_cap_holds_from_the_start() {
        let j = job(&Limits { cpu_rate: Some(2500), ..Limits::default() }).unwrap();
        let cpu = cpu_rate_of(&j);
        let flags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        assert_eq!(cpu.ControlFlags & flags, flags);
        // SAFETY: the CpuRate arm, which the flags select.
        assert_eq!(unsafe { cpu.Anonymous.CpuRate }, 2500);
        // No limit asked for, none set.
        let j = job(&Limits::default()).unwrap();
        assert_eq!(cpu_rate_of(&j).ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, 0);
    }

    /// cpu.weight and cpuset.cpus are the job's weight and affinity, read
    /// back (docs/PORTING.md, row 8).
    #[test]
    fn test_job_weight_and_affinity() {
        use windows_sys::Win32::System::JobObjects::{JOBOBJECT_BASIC_LIMIT_INFORMATION, JobObjectBasicLimitInformation, QueryInformationJobObject};
        let j = job(&Limits { cpu_weight: Some(2), cpus: Some(vec![(0, 0b1)]), ..Limits::default() }).unwrap();
        let cpu = cpu_rate_of(&j);
        let flags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
        assert_eq!(cpu.ControlFlags & flags, flags);
        // SAFETY: the Weight arm, which the flags select.
        assert_eq!(unsafe { cpu.Anonymous.Weight }, 2);
        // SAFETY: plain data.
        let mut basic: JOBOBJECT_BASIC_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: a structure of the size passed, for this class.
        let ok = unsafe {
            QueryInformationJobObject(
                j.as_raw_handle(),
                JobObjectBasicLimitInformation,
                (&raw mut basic).cast(),
                u32::try_from(std::mem::size_of_val(&basic)).unwrap(),
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        assert_ne!(basic.LimitFlags & JOB_OBJECT_LIMIT_AFFINITY, 0);
        assert_eq!(basic.Affinity, 1);
        // A processor the host does not have is refused by Windows too.
        if std::thread::available_parallelism().unwrap().get() < 64 {
            assert!(job(&Limits { cpus: Some(vec![(0, 1 << 63)]), ..Limits::default() }).is_err());
        }
    }

    #[test]
    fn test_copy_exec() {
        let dir = std::env::temp_dir().join(format!("wick-jailer-copy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.exe");
        std::fs::write(&src, b"binary").unwrap();
        let dst = dir.join("dst.exe");
        copy_exec(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"binary");
        // Not over a directory: the open fails, as upstream's (EISDIR).
        let d = dir.join("d");
        std::fs::create_dir(&d).unwrap();
        assert!(matches!(copy_exec(&src, &d).unwrap_err(), JailerError::Open(p, _) if p == d));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // A link planted where the jailer copies Firecracker (upstream's
    // test_exec_destination_path_is_hardlink and _is_symlink): refused, as
    // upstream refuses it (the hard link after its open, the symbolic link
    // at its open, O_NOFOLLOW), and the linked file is left as it was.
    #[test]
    fn test_copy_exec_refuses_a_planted_link() {
        let dir = std::env::temp_dir().join(format!("wick-jailer-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.exe");
        std::fs::write(&src, b"binary").unwrap();
        let target = dir.join("target.txt");
        let content = b"the operator's file".as_slice();
        std::fs::write(&target, content).unwrap();

        let hard = dir.join("hard.exe");
        std::fs::hard_link(&target, &hard).unwrap();
        let r = copy_exec(&src, &hard).map_err(|e| e.to_string());
        let after = std::fs::read(&target).unwrap();
        assert!(
            r.as_ref().is_err_and(|e| e.starts_with("Detected hard link at: ")) && after == content,
            "a hard link: {r:?}; the linked file now holds {:?}",
            String::from_utf8_lossy(&after)
        );

        let sym = dir.join("sym.exe");
        std::os::windows::fs::symlink_file(&target, &sym)
            .expect("a symbolic link (the test needs SeCreateSymbolicLinkPrivilege: run it elevated)");
        let r = copy_exec(&src, &sym);
        assert!(matches!(&r, Err(JailerError::Open(p, _)) if *p == sym), "a symbolic link: {r:?}");
        assert_eq!(std::fs::read(&target).unwrap(), content);

        // One that leads nowhere: nothing is made where it points.
        let dangling = dir.join("dangling.exe");
        std::os::windows::fs::symlink_file(dir.join("nowhere.exe"), &dangling).unwrap();
        let r = copy_exec(&src, &dangling);
        assert!(matches!(&r, Err(JailerError::Open(p, _)) if *p == dangling), "a dangling symbolic link: {r:?}");
        assert!(!dir.join("nowhere.exe").exists());

        // A directory junction (made without a privilege, unlike a symbolic link).
        let junction = dir.join("junction.exe");
        let out = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&dir)
            .output()
            .unwrap();
        assert!(out.status.success(), "mklink /J: {out:?}");
        let r = copy_exec(&src, &junction);
        assert!(matches!(&r, Err(JailerError::Open(p, _)) if *p == junction), "a junction: {r:?}");

        // A file of its own of that name (a jail started again): copied over, whole.
        let old = dir.join("old.exe");
        std::fs::write(&old, b"a longer binary of a previous run").unwrap();
        copy_exec(&src, &old).unwrap();
        assert_eq!(std::fs::read(&old).unwrap(), b"binary");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // A file linked into two jails keeps the first jail's access when the
    // second jail's directory passes its own down: inherited entries are one
    // set per file, an entry of the jail's own is not replaced.
    #[test]
    fn test_a_file_shared_by_two_jails_keeps_both() {
        let base = std::env::temp_dir().join(format!("wick-jailer-share-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (a, b) = (base.join("a"), base.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let user = user_sid().unwrap();
        let (sid_a, sid_b) = ("S-1-9-11-22-33-44", "S-1-9-55-66-77-88");
        let dacl = |sid: &str| format!("D:PAI(A;OICI;FA;;;{user})(A;OICI;FA;;;{sid})");
        std::fs::write(a.join("kernel"), b"k").unwrap();
        std::fs::hard_link(a.join("kernel"), b.join("kernel")).unwrap();
        std::fs::write(a.join("own"), b"o").unwrap();
        assert_eq!(linked_files(&a), vec![a.join("kernel")]);

        let grants = |sid: &str| -> (bool, bool) {
            let e = dacl_entries(&a.join("kernel")).unwrap();
            let has = |inherited: bool| {
                e.iter().any(|(kind, flags, _, s)| {
                    u32::from(*kind) == ACCESS_ALLOWED_ACE_TYPE
                        && s == sid
                        && (u32::from(*flags) & INHERITED_ACE != 0) == inherited
                })
            };
            (has(false), has(true))
        };
        set_security(&a, &dacl(sid_a), false).unwrap();
        explicit_access(&a.join("kernel"), sid_a, true).unwrap();
        // The second jail passes its directory's entries down to its name.
        set_security(&b, &dacl(sid_b), false).unwrap();
        assert_eq!(grants(sid_a), (true, false), "the first jail's own entry is kept");
        assert_eq!(grants(sid_b), (false, true));
        // Taken back, the first jail's entry is gone and the second jail's
        // inherited one stays (not recomputed from the first's directory).
        explicit_access(&a.join("kernel"), sid_a, false).unwrap();
        assert_eq!(grants(sid_a), (false, false));
        assert_eq!(grants(sid_b), (false, true));
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// A suspended process of this user's (cmd.exe, never resumed) for a job
    /// to hold; ended when dropped.
    pub(super) struct Held {
        pub(super) process: OwnedHandle,
        _thread: OwnedHandle,
    }

    impl Drop for Held {
        fn drop(&mut self) {
            // SAFETY: our suspended child.
            unsafe { TerminateProcess(self.process.as_raw_handle(), 1) };
        }
    }

    pub(super) fn held_process() -> Held {
        use windows_sys::Win32::System::Threading::{CreateProcessW, STARTUPINFOW};
        let exe = PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32").join("cmd.exe");
        let mut cmd = wide("cmd.exe");
        // SAFETY: plain data.
        let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
        si.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap();
        // SAFETY: plain data.
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: NUL-terminated application path and command line.
        let ok = unsafe {
            CreateProcessW(
                wide(&exe).as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        };
        assert_ne!(ok, 0, "{}", last_error());
        // SAFETY: handles CreateProcess gave us.
        unsafe {
            Held { process: OwnedHandle::from_raw_handle(pi.hProcess), _thread: OwnedHandle::from_raw_handle(pi.hThread) }
        }
    }

    /// A job without limits, named or not.
    fn plain_job(name: Option<&str>) -> OwnedHandle {
        let name = name.map(wide);
        // SAFETY: no security attributes; a NUL-terminated name or none.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), name.as_ref().map_or(std::ptr::null(), |n| n.as_ptr())) };
        assert!(!h.is_null(), "{}", last_error());
        // SAFETY: a handle we own.
        unsafe { OwnedHandle::from_raw_handle(h) }
    }

    /// Puts the process in the job; the Windows error code when refused.
    fn assign(job: &OwnedHandle, p: &Held) -> Result<(), i32> {
        // SAFETY: handles we own.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), p.process.as_raw_handle()) } == 0 {
            return Err(last_error().raw_os_error().unwrap_or(0));
        }
        Ok(())
    }

    /// Whether the process is in the job (`None`: in any job).
    fn in_job(process: HANDLE, job: Option<&OwnedHandle>) -> bool {
        use windows_sys::Win32::System::JobObjects::IsProcessInJob;
        let mut result = 0;
        // SAFETY: handles we own (or the current process), an out-parameter.
        let ok = unsafe { IsProcessInJob(process, job.map_or(std::ptr::null_mut(), |j| j.as_raw_handle()), &mut result) };
        assert_ne!(ok, 0, "{}", last_error());
        result != 0
    }

    /// Sets a job information class; the Windows error code when refused.
    pub(super) fn set_job<T>(job: &OwnedHandle, class: i32, info: &T) -> Result<(), i32> {
        // SAFETY: a structure of the size passed, for this class.
        let ok = unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                class,
                std::ptr::from_ref(info).cast(),
                u32::try_from(std::mem::size_of::<T>()).unwrap(),
            )
        };
        if ok == 0 { Err(last_error().raw_os_error().unwrap_or(0)) } else { Ok(()) }
    }

    /// On record, what `--parent-cgroup` (`parent`) stands on: whether a
    /// process in a job, as a jail
    /// under a parent job would be, joins the job the jailer makes for a
    /// jail, which sets UI limits. Microsoft Learn says it does not: "the
    /// jobs are nested by default if the system can form a valid job
    /// hierarchy and neither job sets UI limits" ("Nested Jobs"), and the
    /// job a process already in one joins "cannot have UI limits set"
    /// (`AssignProcessToJobObject`). Windows Server 2025, build 26100, took
    /// it, nested (CI run 43359525691: `Ok(())`), so the sentence is not
    /// asserted: the NESTTEST line, with the build it is of, is each run's
    /// answer. What must hold on any build: the process is in the jail's
    /// job exactly when Windows said so, still in its parent, and a job
    /// that sets no UI limits nests.
    #[test]
    #[ignore = "a record of what a jail's job does under a parent job, run alone by CI's windows job"]
    fn test_a_jails_job_under_a_parent_job_on_record() {
        let parent = plain_job(None);
        let p = held_process();
        assign(&parent, &p).unwrap();
        let jail = job(&Limits::default()).unwrap();
        let nested = assign(&jail, &p);
        let windows = std::process::Command::new("cmd")
            .args(["/c", "ver"])
            .output()
            .map_or_else(|e| format!("ver: {e}"), |o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        println!("NESTTEST a jail's job for a process of a parent job: {nested:?} ({windows})");
        assert_eq!(in_job(p.process.as_raw_handle(), Some(&jail)), nested.is_ok());
        assert!(in_job(p.process.as_raw_handle(), Some(&parent)));
        // The control, with a process of its own: the same order nests a
        // job that sets no UI limits.
        let q = held_process();
        assign(&parent, &q).unwrap();
        let inner = plain_job(None);
        assign(&inner, &q).unwrap();
        assert!(in_job(q.process.as_raw_handle(), Some(&parent)));
        assert!(in_job(q.process.as_raw_handle(), Some(&inner)));
    }

    /// On record, no check of the product: what Windows does with the jobs
    /// a parent cgroup would be made of, for the design of `--parent-cgroup`
    /// (which the jailer refuses meanwhile). One NESTTEST line each.
    #[test]
    #[ignore = "a record of what nested Job Objects do, run alone by CI's windows job"]
    fn test_nested_jobs_on_record() {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation, OpenJobObjectW,
            QueryInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::GetProcessAffinityMask;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn VirtualAllocEx(
                process: HANDLE,
                address: *const std::ffi::c_void,
                size: usize,
                kind: u32,
                protect: u32,
            ) -> *mut std::ffi::c_void;
        }
        const MEM_COMMIT_RESERVE: u32 = 0x3000;
        const PAGE_READWRITE: u32 = 4;
        const JOB_OBJECT_ASSIGN_PROCESS_AND_QUERY: u32 = 0x1 | 0x4;
        const MIB: usize = 1 << 20;
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS { UIRestrictionsClass: JAIL_UI_LIMITS };
        let query = |job: &OwnedHandle, class: i32, out: *mut std::ffi::c_void, size: usize| {
            // SAFETY: a structure of the size passed, for this class.
            let ok = unsafe {
                QueryInformationJobObject(job.as_raw_handle(), class, out, u32::try_from(size).unwrap(), std::ptr::null_mut())
            };
            if ok == 0 { Err(last_error().raw_os_error().unwrap_or(0)) } else { Ok(()) }
        };
        let limits = |flags: u32, memory: usize, affinity: usize| {
            // SAFETY: plain data.
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = flags;
            info.BasicLimitInformation.Affinity = affinity;
            info.JobMemoryLimit = memory;
            info
        };
        let commit = |p: &Held, bytes: usize| {
            // SAFETY: our suspended child; the system chooses the address.
            let at = unsafe {
                VirtualAllocEx(p.process.as_raw_handle(), std::ptr::null(), bytes, MEM_COMMIT_RESERVE, PAGE_READWRITE)
            };
            if at.is_null() { Err(last_error().raw_os_error().unwrap_or(0)) } else { Ok(()) }
        };
        let affinity = |p: &Held| {
            let (mut own, mut system) = (0usize, 0usize);
            // SAFETY: our child; out-parameters.
            let ok = unsafe { GetProcessAffinityMask(p.process.as_raw_handle(), &mut own, &mut system) };
            if ok == 0 { Err(last_error().raw_os_error().unwrap_or(0)) } else { Ok(own) }
        };

        // Whether this process, and so each process it starts, is in a job
        // already (a job of CI's runner, a terminal's): the jailer under it.
        // SAFETY: the pseudo-handle of this process.
        let this = unsafe { GetCurrentProcess() };
        println!("NESTTEST this process is in a job: {}", in_job(this, None));
        let p = held_process();
        let inherited = in_job(p.process.as_raw_handle(), None);
        let r = assign(&job(&Limits::default()).unwrap(), &p);
        println!("NESTTEST a new process (in a job at its start: {inherited}) into a jail's job: {r:?}");
        drop(p);

        // UI limits set once the jobs are nested, on the inner and on the
        // outer job.
        let (outer, inner, p) = (plain_job(None), plain_job(None), held_process());
        let nested = assign(&outer, &p).and_then(|()| assign(&inner, &p));
        let on_inner = set_job(&inner, JobObjectBasicUIRestrictions, &ui);
        // SAFETY: plain data.
        let mut back: JOBOBJECT_BASIC_UI_RESTRICTIONS = unsafe { std::mem::zeroed() };
        let read = query(&inner, JobObjectBasicUIRestrictions, (&raw mut back).cast(), std::mem::size_of_val(&back));
        let on_outer = set_job(&outer, JobObjectBasicUIRestrictions, &ui);
        println!(
            "NESTTEST UI limits after nesting ({nested:?}): on the inner job {on_inner:?} (read back {read:?} {:#x}), on the outer job {on_outer:?}",
            back.UIRestrictionsClass
        );
        drop(p);

        // UI limits on the outer job only, set before anything is in it.
        let (outer, inner, p) = (plain_job(None), plain_job(None), held_process());
        let set = set_job(&outer, JobObjectBasicUIRestrictions, &ui);
        let first = assign(&outer, &p);
        let second = assign(&inner, &p);
        println!("NESTTEST an outer job with UI limits ({set:?}): the process into it {first:?}, then into a job without {second:?}");
        drop(p);

        // A parent's memory limit over two jobs under it: 64 MiB, 40 MiB
        // committed in a process of each.
        let parent = plain_job(None);
        let set = set_job(&parent, JobObjectExtendedLimitInformation, &limits(JOB_OBJECT_LIMIT_JOB_MEMORY, 64 * MIB, 0));
        let (ja, jb, pa, pb) = (plain_job(None), plain_job(None), held_process(), held_process());
        let nested = assign(&parent, &pa)
            .and_then(|()| assign(&ja, &pa))
            .and_then(|()| assign(&parent, &pb))
            .and_then(|()| assign(&jb, &pb));
        let (first, second) = (commit(&pa, 40 * MIB), commit(&pb, 40 * MIB));
        // SAFETY: plain data.
        let mut acct: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let read = query(&parent, JobObjectBasicAccountingInformation, (&raw mut acct).cast(), std::mem::size_of_val(&acct));
        // SAFETY: plain data.
        let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let read_ext = query(&parent, JobObjectExtendedLimitInformation, (&raw mut ext).cast(), std::mem::size_of_val(&ext));
        println!(
            "NESTTEST a parent's 64 MiB memory limit ({set:?}) over two jobs ({nested:?}): 40 MiB in the first {first:?}, in the second {second:?}; the parent counts {} active processes ({read:?}), peak {} MiB ({read_ext:?})",
            acct.ActiveProcesses,
            ext.PeakJobMemoryUsed / MIB
        );
        // The control: the same two commits with no limit on the parent.
        let parent = plain_job(None);
        let (ja, jb, pa, pb) = (plain_job(None), plain_job(None), held_process(), held_process());
        let nested = assign(&parent, &pa)
            .and_then(|()| assign(&ja, &pa))
            .and_then(|()| assign(&parent, &pb))
            .and_then(|()| assign(&jb, &pb));
        println!(
            "NESTTEST the same with no limit on the parent ({nested:?}): {:?}, {:?}",
            commit(&pa, 40 * MIB),
            commit(&pb, 40 * MIB)
        );
        drop((pa, pb));

        // Affinity: a job under a parent on processor 0, asked for
        // processor 1 (no subset), then for 0 and 1 (wider).
        if std::thread::available_parallelism().map_or(1, std::num::NonZero::get) >= 2 {
            let (parent, inner, p) = (plain_job(None), plain_job(None), held_process());
            let set = set_job(&parent, JobObjectExtendedLimitInformation, &limits(JOB_OBJECT_LIMIT_AFFINITY, 0, 0b01));
            let nested = assign(&parent, &p).and_then(|()| assign(&inner, &p));
            let under = affinity(&p);
            let other = set_job(&inner, JobObjectExtendedLimitInformation, &limits(JOB_OBJECT_LIMIT_AFFINITY, 0, 0b10));
            let after_other = affinity(&p);
            let wider = set_job(&inner, JobObjectExtendedLimitInformation, &limits(JOB_OBJECT_LIMIT_AFFINITY, 0, 0b11));
            let after_wider = affinity(&p);
            println!(
                "NESTTEST a parent on processor 0 ({set:?}, nested {nested:?}): the process's mask {under:x?}; the inner job asked for processor 1: {other:?}, mask {after_other:x?}; for 0 and 1: {wider:?}, mask {after_wider:x?}"
            );
        } else {
            println!("NESTTEST affinity: one processor, not measured");
        }

        // CPU rate: a hard cap of half on the parent and on the job under
        // it, set and read back (what the two caps give is not timed here).
        let (parent, inner, p) = (plain_job(None), plain_job(None), held_process());
        let nested = assign(&parent, &p).and_then(|()| assign(&inner, &p));
        // SAFETY: plain data.
        let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu.Anonymous.CpuRate = 5000;
        let on_parent = set_job(&parent, JobObjectCpuRateControlInformation, &cpu);
        let on_inner = set_job(&inner, JobObjectCpuRateControlInformation, &cpu);
        // SAFETY: plain data.
        let mut back: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        let read = query(&inner, JobObjectCpuRateControlInformation, (&raw mut back).cast(), std::mem::size_of_val(&back));
        // SAFETY: the CpuRate arm, which the flags set select.
        let rate = unsafe { back.Anonymous.CpuRate };
        println!(
            "NESTTEST a CPU cap of 5000 on a parent {on_parent:?} and on the job under it {on_inner:?} (nested {nested:?}): the inner job reads back {rate} ({read:?})"
        );
        drop(p);

        // A named job: made twice, opened by name, and whether the name
        // outlives the last handle while a process is in the job.
        let name = format!("Local\\wick-nesttest-{}", std::process::id());
        let open = || {
            // SAFETY: a NUL-terminated name.
            let h = unsafe { OpenJobObjectW(JOB_OBJECT_ASSIGN_PROCESS_AND_QUERY, 0, wide(&name).as_ptr()) };
            if h.is_null() {
                return Err(last_error().raw_os_error().unwrap_or(0));
            }
            // SAFETY: a handle we own.
            Ok(unsafe { OwnedHandle::from_raw_handle(h) })
        };
        let first = plain_job(Some(&name));
        let second = plain_job(Some(&name));
        // CreateJobObject of an existing name opens it and says so.
        let again = last_error().raw_os_error();
        let opened = open().map(drop);
        let p = held_process();
        let assigned = assign(&first, &p);
        drop((first, second));
        let held_by_a_process = open().map(drop);
        drop(p);
        let empty = open().map(drop);
        println!(
            "NESTTEST a named job: made again {again:?}, opened by name {opened:?}; a process in it {assigned:?}; opened with no handle left and the process in it {held_by_a_process:?}; after the process ended {empty:?}"
        );
    }
}
