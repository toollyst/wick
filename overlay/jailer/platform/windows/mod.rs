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
//!   restricting SIDs, so the user's files are denied, and low integrity, so
//!   nothing at medium integrity can be written. WHP works for such a process
//!   (it is refused inside an AppContainer). The process starts with an
//!   initial impersonation token on its main thread, the same restricted
//!   token with the user's SID, for the loader to initialise; Firecracker
//!   reverts to the lockdown token first thing (`vmm::ext::jail`), the
//!   pattern of the Chromium sandbox.
//! - **The jail directory** grants the restricted token (`RESTRICTED`) full
//!   access, inherited, and has a low mandatory label.
//! - **cgroups are a Job Object** ([`cgroup`](super::cgroup)): job memory
//!   limit, CPU rate hard cap, active process limit; the job kills
//!   Firecracker when the jailer goes and limits its UI access.
//! - **No exec**: the jailer starts Firecracker suspended in the job with the
//!   tokens, waits for it, removes the jail's drive and exits with its status.
//!
//! Refused, never accepted without effect: `--netns` and `--new-pid-ns`
//! (no namespaces), `--daemonize` (the jailer owns the job and the drive
//! while Firecracker runs), `--resource-limit fsize=` and a `no-file=` other
//! than the default (Windows cannot limit file sizes or the number of
//! handles; the default is not enforced either).

use std::ffi::{CStr, OsStr};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    LocalFree, SetHandleInformation,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx,
    GetLengthSid, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl, GetTokenInformation,
    LABEL_SECURITY_INFORMATION, LUA_TOKEN, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS,
    TOKEN_DEFAULT_DACL, TOKEN_GROUPS,
    TOKEN_MANDATORY_LABEL, TOKEN_USER, TokenDefaultDacl, TokenGroups, TokenImpersonation,
    TokenIntegrityLevel, TokenUser, UNPROTECTED_DACL_SECURITY_INFORMATION, ACL,
};
use windows_sys::Win32::Storage::FileSystem::{
    DDD_EXACT_MATCH_ON_REMOVE, DDD_REMOVE_DEFINITION, DefineDosDeviceW, GetLogicalDrives,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
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
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, SetThreadToken, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

/// `SE_GROUP_INTEGRITY` (winnt.h).
const SE_GROUP_INTEGRITY: u32 = 0x20;
/// `SE_GROUP_LOGON_ID` (winnt.h).
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

use crate::JailerError;

/// Environment variable through which Firecracker takes the jail over
/// (`vmm::ext::jail::ENV`).
const JAIL_ENV: &str = "WICK_JAIL";
/// Bytes every binary that takes the jail over carries
/// (`vmm::ext::jail::HANDOVER_MARK`): without it, a program would keep the
/// initial impersonation token (the user's SID) on its main thread.
const HANDOVER_MARK: &[u8] = b"wick-jail-handover:v1\0";
/// Firecracker's temporary directory in the jail: memfds are unlinked files
/// there on Windows (crates/compat/memfd); on Linux they are kernel objects.
const JAIL_TMP: &str = "tmp";

/// Restricting SIDs of the lockdown token: what any process of the session
/// may have, never the user's own SID. `RESTRICTED` (S-1-5-12) is the one the
/// jail directory and the token's default DACL grant.
const RESTRICTING_SIDS: [&str; 5] = [
    "S-1-1-0",      // Everyone
    "S-1-5-32-545", // Users
    "S-1-5-12",     // RESTRICTED
    "S-1-5-11",     // Authenticated Users
    "S-1-5-4",      // Interactive
];
/// The default DACL of both tokens: what the process creates (its own process
/// and threads first) is open to SYSTEM, the restricted SID and the owner.
const DEFAULT_DACL: &str = "D:(A;;GA;;;SY)(A;;GA;;;RC)(A;;GA;;;OW)";
/// The jail directory: full access for the restricted token, inherited, on
/// top of what the directory inherits from its parent.
const JAIL_DACL: &str = "D:AI(A;OICI;FA;;;RC)";
/// Low mandatory label, inherited, no write up.
const JAIL_LABEL: &str = "S:(ML;OICI;NW;;;LW)";
/// Low integrity.
const LOW_INTEGRITY_SID: &str = "S-1-16-4096";

/// What the Windows backend refuses, or a Windows step that failed.
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error(
        "--{0} is not supported on Windows: {1}. The jailer never accepts an isolation option it \
         cannot enforce."
    )]
    Unsupported(&'static str, &'static str),
    #[error(
        "--cgroup {0} is not supported on Windows (supported: memory.max, cpu.max and pids.max \
         with --cgroup-version 2; memory.limit_in_bytes, cpu.cfs_quota_us, cpu.cfs_period_us and \
         pids.max with --cgroup-version 1). The jailer never accepts a limit it cannot enforce."
    )]
    UnsupportedCgroup(String),
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub memory_bytes: Option<u64>,
    /// Hundredths of a percent of all processors (`CpuRate`).
    pub cpu_rate: Option<u32>,
    pub processes: Option<u32>,
}

static LIMITS: Mutex<Limits> = Mutex::new(Limits {
    memory_bytes: None,
    cpu_rate: None,
    processes: None,
});

pub(crate) fn set_limits(limits: Limits) {
    *LIMITS.lock().unwrap() = limits;
}

/// `--netns`: Windows has no network namespaces.
pub fn join_netns(_path: &str) -> Result<(), JailerError> {
    Err(HostError::Unsupported(
        "netns",
        "Windows has no network namespaces; give Firecracker a Unix stream network endpoint \
         inside the jail",
    )
    .into())
}

/// `--new-pid-ns`: Windows has no PID namespaces.
pub fn new_pid_ns() -> Result<(), JailerError> {
    Err(HostError::Unsupported(
        "new-pid-ns",
        "Windows has no PID namespaces; the jailed Firecracker is alone in its Job Object",
    )
    .into())
}

/// `--daemonize`: the jailer stays while Firecracker runs.
pub fn daemonize() -> Result<(), JailerError> {
    Err(HostError::Unsupported(
        "daemonize",
        "Windows has no exec, so the jailer stays while Firecracker runs: it owns the Job Object \
         that limits it and removes the jail's drive when it exits; start the jailer detached \
         instead",
    )
    .into())
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
/// inherited, a low mandatory label), maps a free drive letter to it and
/// makes its root the current directory. Upstream's absolute paths resolve
/// inside the jail from here on.
pub(crate) fn enter_jail(path: &Path) -> Result<(), JailerError> {
    let root = plain(path);
    let fail = |what, err| HostError::Jail(root.clone(), what, err);
    std::fs::create_dir_all(&root).map_err(|e| fail("create the directory", e))?;
    set_security(&root, JAIL_DACL, false).map_err(|e| fail("grant the restricted token", e))?;
    set_security(&root, JAIL_LABEL, true).map_err(|e| fail("set the low integrity label", e))?;
    std::fs::create_dir_all(root.join(JAIL_TMP)).map_err(|e| fail("create tmp", e))?;
    let drive = map_drive(&root).map_err(JailerError::from)?;
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
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION
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
            return Ok(drive);
        }
    }
    Err(HostError::NoDriveLetter)
}

/// Removes the jail's drive mapping.
fn unmap_drive(jail: &Jail) {
    // SAFETY: NUL-terminated device name and target; removes our definition only.
    unsafe {
        DefineDosDeviceW(
            DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
            wide(&jail.drive).as_ptr(),
            wide(&jail.root).as_ptr(),
        )
    };
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

    let sids: Vec<Sid> = RESTRICTING_SIDS.iter().map(|s| Sid::new(s)).collect::<Result<_, _>>()?;
    let mut restricting: Vec<SID_AND_ATTRIBUTES> =
        sids.iter().map(|s| SID_AND_ATTRIBUTES { Sid: s.0, Attributes: 0 }).collect();
    restricting.push(SID_AND_ATTRIBUTES { Sid: logon, Attributes: 0 });
    let primary = restricted(process_h, &restricting)?;
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

/// A restricted token: no privileges, `restricting` SIDs, the default DACL
/// and low integrity.
fn restricted(from: HANDLE, restricting: &[SID_AND_ATTRIBUTES]) -> Result<OwnedHandle, HostError> {
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: a token we own and a valid SID array.
    if unsafe {
        CreateRestrictedToken(
            from,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
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

    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string and an out-pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(DEFAULT_DACL).as_ptr(),
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

    let low = Sid::new(LOW_INTEGRITY_SID)?;
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

/// A Job Object with the cgroup limits: Firecracker dies with the jailer
/// (kill on close) and has no UI access.
fn job(limits: Limits) -> Result<OwnedHandle, HostError> {
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
    if let Some(n) = limits.processes {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = n;
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
    if let Some(rate) = limits.cpu_rate {
        // SAFETY: plain data.
        let mut cpu: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu.Anonymous.CpuRate = rate;
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
/// current directory. Writes its pid to the pid file, waits for it, removes
/// the jail's drive and exits with its status. Returns only on failure.
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

    let drive_root = format!("{}\\", jail.drive);
    let mut argv = vec![format!("{drive_root}{}", name.to_string_lossy())];
    argv.extend(args.iter().cloned());
    let mut cmd: Vec<u16> = wide(command_line(&argv));
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let tmp = format!("{drive_root}{JAIL_TMP}");
    let mut env: Vec<u16> = Vec::new();
    for var in [
        format!("{JAIL_ENV}={uid}:{gid}:{}", chroot_dir.display()),
        format!("SystemRoot={system_root}"),
        format!("TEMP={tmp}"),
        format!("TMP={tmp}"),
    ] {
        env.extend(var.encode_utf16());
        env.push(0);
    }
    env.push(0);

    let tokens = tokens()?;
    let job = job(*LIMITS.lock().unwrap())?;

    // The standard handles, inheritable, and only them.
    let mut handles: Vec<HANDLE> = Vec::new();
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: plain call.
        let h = unsafe { GetStdHandle(which) };
        if !h.is_null() && h != INVALID_HANDLE_VALUE && !handles.contains(&h) {
            // SAFETY: one of our standard handles.
            if unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } != 0 {
                handles.push(h);
            }
        }
    }
    let mut size = 0usize;
    // SAFETY: a size query.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    let mut attrs = vec![0u64; size.div_ceil(8)];
    let list: LPPROC_THREAD_ATTRIBUTE_LIST = attrs.as_mut_ptr().cast();
    // SAFETY: a buffer of the size asked for.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) } == 0 {
        return Err(HostError::Spawn("InitializeProcThreadAttributeList", last_error()));
    }
    if !handles.is_empty() {
        // SAFETY: the handle array outlives the process creation.
        if unsafe {
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
            return Err(HostError::Spawn("PROC_THREAD_ATTRIBUTE_HANDLE_LIST", last_error()));
        }
    }
    // SAFETY: plain data.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap();
    si.lpAttributeList = list;
    if !handles.is_empty() {
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        // SAFETY: plain calls.
        unsafe {
            si.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
            si.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
            si.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        }
    }
    // SAFETY: plain data.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let no_sa: *const SECURITY_ATTRIBUTES = std::ptr::null();
    // SAFETY: NUL-terminated application path, command line, environment and
    // directory; the attribute list and tokens outlive the call.
    let created = unsafe {
        CreateProcessAsUserW(
            tokens.primary.as_raw_handle(),
            wide(&exe).as_ptr(),
            cmd.as_mut_ptr(),
            no_sa,
            no_sa,
            i32::from(!handles.is_empty()),
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
            env.as_ptr().cast(),
            wide(&drive_root).as_ptr(),
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
    // Upstream's pid file holds the jailer's pid, which an exec keeps; here it
    // is Firecracker's.
    let pid_file = jail.root.join(format!("{}.pid", name.to_string_lossy()));
    if let Err(e) = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&pid_file)
        .and_then(|mut f| write!(f, "{}", pi.dwProcessId))
    {
        return Err(kill("the pid file", e));
    }
    // SAFETY: the suspended main thread.
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        return Err(kill("ResumeThread", last_error()));
    }
    drop(thread);
    // SAFETY: our child.
    unsafe { WaitForSingleObject(process.as_raw_handle(), INFINITE) };
    let mut code = 1u32;
    // SAFETY: our child, ended.
    unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) };
    unmap_drive(jail);
    drop(job);
    std::process::exit(code.cast_signed());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsupported_isolation_is_refused() {
        for (err, flag) in [
            (join_netns("x").unwrap_err(), "netns"),
            (new_pid_ns().unwrap_err(), "new-pid-ns"),
            (daemonize().unwrap_err(), "daemonize"),
        ] {
            assert!(matches!(err, JailerError::Host(HostError::Unsupported(f, _)) if f == flag), "{flag}");
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
        job(Limits { memory_bytes: Some(256 << 20), cpu_rate: Some(5000), processes: Some(1) }).unwrap();
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
