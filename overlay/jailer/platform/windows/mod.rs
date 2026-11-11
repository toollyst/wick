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
//!   named, where Firecracker makes its network endpoints and which the
//!   jail's SID is granted on, and the jail's copy of Firecracker gets no IP
//!   networking at all (Windows Filtering Platform). Needs an elevated
//!   jailer, as `setns` needs root.
//!
//! Refused, never accepted without effect: `--resource-limit fsize=` and a
//! `no-file=` other than the default (Windows cannot limit file sizes or the
//! number of handles; the default is not enforced either).

use std::ffi::{CStr, OsStr};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    DuplicateHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED, FILETIME, GetLastError, HANDLE,
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
    AdjustTokenPrivileges, CreateRestrictedToken, DACL_SECURITY_INFORMATION, DuplicateTokenEx,
    LUID_AND_ATTRIBUTES, LookupPrivilegeNameW, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, TokenPrivileges,
    GetLengthSid, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl, GetTokenInformation,
    LABEL_SECURITY_INFORMATION, LUA_TOKEN, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS,
    TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_QUERY,
    TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenDefaultDacl, TokenGroups, TokenImpersonation,
    TokenIntegrityLevel, TokenUser, PROTECTED_DACL_SECURITY_INFORMATION, ACL,
};
use windows_sys::Win32::Storage::FileSystem::{
    DDD_EXACT_MATCH_ON_REMOVE, DDD_RAW_TARGET_PATH, DDD_REMOVE_DEFINITION, DefineDosDeviceW, GetLogicalDrives,
};
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
    SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, GetProcessTimes, INFINITE, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, SetEvent,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, SetThreadToken, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

mod console;
mod netns;

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
         memory.limit_in_bytes, cpu.cfs_quota_us, cpu.cfs_period_us, cpu.shares, cpuset.cpus and \
         cpuset.mems with --cgroup-version 1). The jailer never accepts a limit it cannot enforce."
    )]
    UnsupportedCgroup(String),
    #[error("--cgroup {0} is refused on Windows: {1}. The jailer never accepts a limit it cannot enforce.")]
    ImpossibleCgroup(String, &'static str),
    #[error("--cgroup {0}: {1}")]
    CgroupValue(String, &'static str),
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

/// The jail the jailer entered: its directory and the drive mapped to it.
struct Jail {
    root: PathBuf,
    drive: String,
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
}

static LIMITS: Mutex<Limits> = Mutex::new(Limits {
    memory_bytes: None,
    cpu_rate: None,
    cpu_weight: None,
    cpus: None,
});

pub(crate) fn set_limits(limits: Limits) {
    *LIMITS.lock().unwrap() = limits;
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

/// Grants the jail's SID full access to `dir` and what is made in it, keeping
/// the other entries (another jail sharing the network keeps its own), and
/// labels it with the jail's integrity level, so that the jailed process can
/// make its endpoints there: an object without a label is medium, which a
/// jailed process may not write to.
fn grant_to_jail(dir: &Path) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SetEntriesInAclW,
        TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    let sid = Sid::new(vm_sid()).map_err(|e| io::Error::other(e.to_string()))?;
    let mut old: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path; out-pointers for the DACL and its descriptor.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide(dir).as_ptr(),
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
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.0.cast(),
        },
    };
    let mut new: *mut ACL = std::ptr::null_mut();
    // SAFETY: one entry; the old ACL lives in `sd`; an out-pointer.
    let rc = unsafe { SetEntriesInAclW(1, &entry, old, &mut new) };
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(sd) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    // SAFETY: a NUL-terminated path; the new ACL, freed below.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide(dir).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new,
            std::ptr::null(),
        )
    };
    // SAFETY: allocated by SetEntriesInAclW.
    unsafe { LocalFree(new.cast()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc.cast_signed()));
    }
    set_security(dir, JAIL_LABEL, true)
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
    let keeper = spawn_jailer(&argv, std_handles, &[event.as_raw_handle()], 0)?;
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
    // The detached jailer runs on; its handle is not needed.
    drop(spawn_jailer(&argv, [nul; 3], &[], DETACHED_PROCESS)?);
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

/// Copies the operator's binary into the jail, as upstream does: a copy, so
/// two Firecracker processes never share its memory. Never through a link
/// planted at the destination.
pub fn copy_exec(src: &Path, dst: &Path) -> Result<(), JailerError> {
    if let Ok(meta) = std::fs::symlink_metadata(dst) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(JailerError::HardLink(dst.to_owned()));
        }
    }
    let copy_err = |err| JailerError::Copy(src.to_owned(), dst.to_owned(), err);
    let mut from = std::fs::File::open(src).map_err(|err| JailerError::Open(src.to_owned(), err))?;
    let mut to = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(dst)
        .map_err(|err| JailerError::Open(dst.to_owned(), err))?;
    io::copy(&mut from, &mut to).map_err(copy_err)?;
    Ok(())
}

/// Upstream's resource limits. Windows cannot limit the size of the files a
/// process writes or its number of handles: an explicit limit is refused, and
/// the default number of files (which upstream always sets) is not enforced.
pub fn install_resource_limits(
    file_size: Option<u64>,
    no_file: u64,
    default_no_file: u64,
) -> Result<(), JailerError> {
    if file_size.is_some() {
        return Err(HostError::UnsupportedLimit(
            "fsize",
            "Windows cannot limit the size of the files a process writes",
        )
        .into());
    }
    if no_file != default_no_file {
        return Err(HostError::UnsupportedLimit(
            "no-file",
            "Windows cannot limit the number of handles a process opens",
        )
        .into());
    }
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
    set_security(&root, &jail_dacl(&user), false)
        .map_err(|e| fail("grant the jail's SID", e))?;
    set_security(&root, JAIL_LABEL, true).map_err(|e| fail("set the jail's integrity label", e))?;
    std::fs::create_dir_all(root.join(JAIL_TMP)).map_err(|e| fail("create tmp", e))?;
    let drive = map_drive(&root).map_err(JailerError::from)?;
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
    *jail = Some(Jail { root, drive });
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

/// Maps the highest free drive letter to `root`.
fn map_drive(root: &Path) -> Result<String, HostError> {
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
    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: the buffer holds a TOKEN_USER; an out-pointer.
    if unsafe { ConvertSidToStringSidW((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a NUL-terminated string allocated by the conversion.
    let sid = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        s
    };
    Ok(sid)
}

/// A token information class, in a buffer of the size the token asks for.
fn token_info(token: HANDLE, class: i32) -> Result<Vec<u64>, HostError> {
    let mut len = 0u32;
    // SAFETY: a size query.
    unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
    // SAFETY: plain call.
    if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
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

/// "Lock pages in memory": guest memory on large pages (`huge_pages`) needs
/// it, as huge pages on Linux need a pool an administrator reserved.
const LOCK_MEMORY: &str = "SeLockMemoryPrivilege";

/// The privileges a jailed process keeps, when the operator's token holds
/// them: `SeChangeNotifyPrivilege` (traversal, the one `DISABLE_MAX_PRIVILEGE`
/// keeps) and [`LOCK_MEMORY`], which an administrator grants an account for
/// large pages. Every other privilege is deleted from the jail's tokens.
const KEPT_PRIVILEGES: [&str; 2] = ["SeChangeNotifyPrivilege", LOCK_MEMORY];

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

/// Enables the privilege `p` in `token`, which holds it.
fn enable_privilege(token: HANDLE, p: LUID_AND_ATTRIBUTES) -> Result<(), HostError> {
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: p.Luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    // SAFETY: a token we own and one privilege.
    let ok = unsafe { AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
    // It succeeds without the privilege, and says so.
    // SAFETY: plain call.
    if ok == 0 || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        return Err(HostError::Spawn("enabling SeLockMemoryPrivilege in the jail's token", last_error()));
    }
    Ok(())
}

/// A restricted token: no privileges but [`KEPT_PRIVILEGES`] (with
/// [`LOCK_MEMORY`] enabled, so a jailed Firecracker maps large pages without
/// adjusting a token it may not open), `restricting` SIDs, the default DACL
/// and the jail's integrity level.
fn restricted(from: HANDLE, restricting: &[SID_AND_ATTRIBUTES]) -> Result<OwnedHandle, HostError> {
    let held = privileges(from)?;
    let delete: Vec<LUID_AND_ATTRIBUTES> =
        held.iter().filter(|(n, _)| !KEPT_PRIVILEGES.contains(&n.as_str())).map(|(_, p)| *p).collect();
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: a token we own, a valid privilege array and a valid SID array.
    if unsafe {
        CreateRestrictedToken(
            from,
            LUA_TOKEN,
            0,
            std::ptr::null(),
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
    if let Some((_, lock)) = held.iter().find(|(n, _)| n == LOCK_MEMORY) {
        enable_privilege(t.as_raw_handle(), *lock)?;
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

/// A Job Object with the cgroup limits: Firecracker dies with the jailer
/// (kill on close) and has no UI access.
fn job(limits: &Limits) -> Result<OwnedHandle, HostError> {
    // SAFETY: an unnamed job.
    let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if h.is_null() {
        return Err(HostError::Spawn("CreateJobObject", last_error()));
    }
    // SAFETY: a handle we own.
    let job = unsafe { OwnedHandle::from_raw_handle(h) };
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
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
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
/// in `job`, with the initial token on its main thread, `vars` as its whole
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
    // SAFETY: handles we own.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
        return Err(kill("AssignProcessToJobObject", last_error()));
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

    // --netns: the network directory opened to the jail, named to
    // Firecracker, and no IP networking for the jail's binary, from before
    // it starts until the jailer ends (the filter's session is the jailer's).
    let netns = NETNS.lock().unwrap().take();
    let mut vars = Vec::new();
    let _net_filter = match netns {
        Some((dir, mut filter)) => {
            grant_to_jail(&dir)
                .map_err(|e| HostError::Netns(dir.clone(), format!("cannot open the network to the jail: {e}")))?;
            vars.push(format!("{NETNS_ENV}={}", dir.display()));
            filter.block(&exe).map_err(|e| HostError::Netns(dir.clone(), e.to_string()))?;
            Some(filter)
        }
        None => None,
    };

    let drive_root = format!("{}\\", jail.drive);
    let mut argv = vec![format!("{drive_root}{}", name.to_string_lossy())];
    argv.extend(cpu_start_of_new_process(args));
    let cmd = command_line(&argv);
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let tmp = format!("{drive_root}{JAIL_TMP}");
    vars.extend([
        format!("{JAIL_ENV}={uid}:{gid}:{}", chroot_dir.display()),
        format!("SystemRoot={system_root}"),
        format!("TEMP={tmp}"),
        format!("TMP={tmp}"),
    ]);

    let tokens = tokens()?;
    let job = job(&limits)?;

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
            Some(spawn_jailed(&exe, &cmd, &api_vars, std_handles, &handles, &drive_root, &tokens, &job)?)
        }
        None => None,
    };
    let api_handle = api_process.as_ref().map(|p| p.process.as_raw_handle());
    let mut fc_vars = vars.clone();
    let mut fc_handles = handles.clone();
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
    let fc = match spawn_jailed(&exe, &cmd, &fc_vars, std_handles, &fc_handles, &drive_root, &tokens, &job) {
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
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&pid_file)
        .and_then(|mut f| write!(f, "{}", fc.pid))
    {
        return Err(kill("the pid file", e));
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
    // --new-pid-ns: Firecracker runs and its pid is in the pid file; the
    // jailer that handed over to this keeper exits 0 (`new_pid_ns`).
    if let Some(event) = KEEPER_EVENT.lock().unwrap().take() {
        // SAFETY: the event this keeper inherited; set once, then closed.
        unsafe {
            SetEvent(event as HANDLE);
            windows_sys::Win32::Foundation::CloseHandle(event as HANDLE);
        }
    }
    // SAFETY: our child.
    unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    let mut code = 1u32;
    // SAFETY: our child, ended.
    unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) };
    terminal.finish();
    unmap_drive(jail);
    drop(job);
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

    // The jail's SID is granted on a network directory without disturbing
    // the entries there (another jail's), and the directory gets the jail's
    // label.
    #[test]
    fn test_grant_to_jail_keeps_other_entries() {
        let dir = std::env::temp_dir().join(format!("wick-jailer-grant-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sddl = |path: &Path, label: bool| -> String {
            use windows_sys::Win32::Security::Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            };
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let info = if label { LABEL_SECURITY_INFORMATION } else { DACL_SECURITY_INFORMATION };
            // SAFETY: a NUL-terminated path and out-pointers.
            let rc = unsafe {
                GetNamedSecurityInfoW(
                    wide(path).as_ptr(),
                    SE_FILE_OBJECT,
                    info,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut sd,
                )
            };
            assert_eq!(rc, 0);
            let mut text: *mut u16 = std::ptr::null_mut();
            let mut len = 0u32;
            // SAFETY: the descriptor from above; out-pointers.
            let ok = unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, info, &mut text, &mut len)
            };
            assert_ne!(ok, 0);
            // SAFETY: `len` characters allocated by the conversion.
            let s = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(text, len as usize)) };
            // SAFETY: allocated by the calls above.
            unsafe {
                LocalFree(text.cast());
                LocalFree(sd);
            }
            s.trim_end_matches('\0').to_owned()
        };
        let before = sddl(&dir, false);
        grant_to_jail(&dir).unwrap();
        let after = sddl(&dir, false);
        assert!(after.contains(vm_sid()), "{after}");
        // Every entry there before is still there.
        for ace in before.trim_start_matches("D:").split_inclusive(')').filter(|a| a.starts_with('(')) {
            assert!(after.contains(ace), "{ace} lost: {after}");
        }
        assert!(sddl(&dir, true).contains(JAIL_INTEGRITY_SID));
        // A second grant (another jail of the same jailer: the same SID) changes nothing more.
        grant_to_jail(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
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
        install_resource_limits(None, 2048, 2048).unwrap();
        assert!(matches!(
            install_resource_limits(Some(1 << 20), 2048, 2048).unwrap_err(),
            JailerError::Host(HostError::UnsupportedLimit("fsize", _))
        ));
        assert!(matches!(
            install_resource_limits(None, 100, 2048).unwrap_err(),
            JailerError::Host(HostError::UnsupportedLimit("no-file", _))
        ));
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

    /// The jail's tokens hold no privilege but traversal and, when the
    /// operator's account holds it, "Lock pages in memory", enabled
    /// (docs/PORTING.md, row 10); this process's token has others.
    #[test]
    fn test_tokens_keep_only_traversal_and_lock_memory() {
        let mut own: HANDLE = std::ptr::null_mut();
        // SAFETY: our own token.
        assert_ne!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own) }, 0);
        // SAFETY: a token handle we own.
        let own = unsafe { OwnedHandle::from_raw_handle(own) };
        let mine: Vec<String> = privileges(own.as_raw_handle()).unwrap().into_iter().map(|(n, _)| n).collect();
        assert!(mine.iter().any(|n| !KEPT_PRIVILEGES.contains(&n.as_str())), "{mine:?}");
        let lock = mine.iter().any(|n| n == LOCK_MEMORY);
        let mut want = vec![("SeChangeNotifyPrivilege".to_string(), true)];
        if lock {
            want.push((LOCK_MEMORY.to_string(), true));
        }
        let t = tokens().unwrap();
        for token in [&t.primary, &t.initial] {
            let mut kept: Vec<(String, bool)> = privileges(token.as_raw_handle())
                .unwrap()
                .into_iter()
                .map(|(n, p)| (n, p.Attributes & SE_PRIVILEGE_ENABLED != 0))
                .collect();
            kept.sort();
            assert_eq!(kept, want, "the jail's token, from {mine:?}");
        }
        if !lock {
            eprintln!("this account lacks {LOCK_MEMORY}: only its absence from the jail was checked");
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
        // Not over a directory.
        let d = dir.join("d");
        std::fs::create_dir(&d).unwrap();
        assert!(matches!(copy_exec(&src, &d).unwrap_err(), JailerError::HardLink(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
