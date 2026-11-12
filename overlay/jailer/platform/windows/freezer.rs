// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The jail's freezer: upstream's cgroup freezer files, for every jail.
//!
//! On Linux a jail's cgroup has the freezer's files: `freezer.state` (v1,
//! upstream's default: write `FROZEN` or `THAWED`) or `cgroup.freeze` (write
//! `1` or `0`) and `cgroup.events` (`frozen 0|1`) with v2. Whoever may write
//! them (root, or a delegated user) does so at any time, and the kernel stops
//! every task of the cgroup, invisibly to them, and starts them again.
//! Windows has no cgroups, so the jailer makes the same files, for the jail's
//! cgroup version, in `<chroot-base>\<exec>\<id>\` next to `root\` (where the
//! jail cannot write: `jailer-test.ps1 links`), and keeps them itself: the
//! jailer stays for the jail's whole life (it waits for Firecracker and holds
//! its Job Object, `platform::exec`), so it watches the directory
//! (`FindFirstChangeNotification`) while it waits.
//!
//! **Freezing is the Job Object's**, both of the jail's processes at once,
//! and a process that joins the job while it is frozen is frozen too
//! ([`JobFreeze`]). Measured on Windows Server 2022 build 20348 elevated and
//! on a LUA token (`jailer-test.ps1 freeze`), and on Windows 11 build 26300
//! unelevated (`tools/windows/job-freeze-probe.ps1`):
//!
//! - a frozen job's processes use no CPU; its parent's wait sees nothing;
//! - a process made suspended, put in the frozen job and resumed does not
//!   run: the jail is frozen before Firecracker's first instruction when the
//!   file says so at the start;
//! - a second freeze, or a second thaw, is refused (`STATUS_INVALID_PARAMETER`)
//!   and changes nothing; the jailer keeps the state and never makes one;
//! - `TerminateProcess` ends a frozen process, with the code given; closing
//!   the job's last handle (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) ends them
//!   all: the jailer's death ends a frozen jail.
//!
//! The job information class that freezes is **not documented by
//! Microsoft**: the SDK lists class 18 as `JobObjectReserved1Information`.
//! Its name and layout are from System Informer's headers ([`JobFreeze`]). So
//! the jailer proves it on every start ([`self_check`]): a throwaway process
//! is frozen in a job of its own, its CPU time must stand still, and thawed;
//! a host where that fails refuses every jail, with the status and the
//! Windows build, rather than run one whose freezer would not work.
//!
//! The documented alternatives cannot do what the cgroup does: `SuspendThread`
//! suspends one thread (a thread or process the jail makes meanwhile runs);
//! `NtSuspendProcess` (undocumented as well) is per process, and nested (two
//! suspends need two resumes); a debugger (`DebugActiveProcess`) is seen by
//! the process and kills it when it goes.
//!
//! Where the jailer cannot do what the kernel does, it says so:
//!
//! - a write of an invalid value cannot fail as on Linux (EINVAL). It is
//!   ignored and, once the file has kept it for [`fv::SETTLE_MS`], the file is
//!   restored to the current state, with a line on the jailer's stderr
//!   (Firecracker's console, `NUL` with `--daemonize`): the value read back
//!   is the state;
//! - a file that is not a regular file with one name, owned by SYSTEM, the
//!   administrators or the operator, is invalid (and replaced). The files'
//!   DACL grants SYSTEM, the administrators and the operator, nobody else;
//! - if a freeze or thaw the file asks for fails, the jail is killed rather
//!   than left as it was against the request.
//!
//! `--cgroup freezer.state=FROZEN` (v1) stops the jailer at the cgroup step,
//! before the jail, `--daemonize` and `--new-pid-ns`, as on Linux, where the
//! jailer freezes itself there: the files are made first and the jailer waits
//! until they say `THAWED` ([`at_cgroup_step`]). The jailer that
//! `--daemonize` or `--new-pid-ns` starts again runs the cgroup step again:
//! it takes the files over from the one that made them ([`handover`]) and
//! waits only if they say `FROZEN` again.

use std::ffi::c_void;
use std::io::{self, Read, Seek, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, GENERIC_READ,
    GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
    WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, CreateHardLinkW, DeleteFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FindCloseChangeNotification, FindFirstChangeNotificationW,
    FindNextChangeNotification, GetFileInformationByHandle,
    RemoveDirectoryW,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CancelWaitableTimer, CreateProcessW,
    CreateWaitableTimerW, GetProcessTimes, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, SetWaitableTimer,
    TerminateProcess, WaitForSingleObject,
};

use super::super::freezer_values as fv;
pub(crate) use fv::{State, Version};
use super::{last_error, plain, wide};

// ------------------------------------------------------------- the OS call

/// `JobObjectFreezeInformation`, the job information class that freezes and
/// thaws a job. Not in Microsoft's documentation, where class 18 is
/// `JobObjectReserved1Information` (the Windows SDK metadata, windows-sys
/// 0.61.2 `JobObjects`). Name, number and layout are System Informer's
/// (github.com/winsiderss/phnt, ntpsapi.h, read 2026-11-12 on master):
///
/// ```c
/// #define JobObjectFreezeInformation 18 // qs: JOBOBJECT_FREEZE_INFORMATION
/// typedef struct _JOBOBJECT_FREEZE_INFORMATION {
///     union { ULONG Flags; struct { ULONG FreezeOperation : 1; ULONG FilterOperation : 1;
///                                   ULONG SwapOperation : 1; ULONG Reserved : 29; }; };
///     BOOLEAN Freeze; BOOLEAN Swap; UCHAR Reserved0[2];
///     JOBOBJECT_WAKE_FILTER WakeFilter; // { ULONG HighEdgeFilter; ULONG LowEdgeFilter; }
/// } JOBOBJECT_FREEZE_INFORMATION;
/// ```
///
/// Everything that freezes goes through [`JobFreeze`]; nothing else here
/// depends on how.
const JOB_OBJECT_FREEZE_INFORMATION: i32 = 18;
/// `FreezeOperation`, the bit of `Flags` that asks for `Freeze`.
const FREEZE_OPERATION: u32 = 1;

#[repr(C)]
#[derive(Debug, Default)]
struct JobObjectFreezeInformation {
    flags: u32,
    freeze: u8,
    swap: u8,
    reserved0: [u8; 2],
    wake_filter: [u32; 2],
}

/// `RTL_OSVERSIONINFOW`, for the Windows build in the self-check's error.
#[repr(C)]
struct OsVersionInfo {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    csd: [u16; 128],
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtSetInformationJobObject(job: HANDLE, class: i32, info: *const c_void, len: u32) -> i32;
    fn RtlGetVersion(info: *mut OsVersionInfo) -> i32;
}

/// Freezes and thaws a job, as a whole.
pub(crate) trait JobFreeze {
    /// Freezes (`true`) or thaws the job: the NTSTATUS of a refusal.
    fn set(&mut self, frozen: bool) -> Result<(), i32>;
}

/// A Job Object's handle.
pub(crate) struct Job(pub(crate) HANDLE);

impl JobFreeze for Job {
    fn set(&mut self, frozen: bool) -> Result<(), i32> {
        let info = JobObjectFreezeInformation { flags: FREEZE_OPERATION, freeze: u8::from(frozen), ..Default::default() };
        // SAFETY: a job handle and a structure of the size passed.
        let status = unsafe {
            NtSetInformationJobObject(
                self.0,
                JOB_OBJECT_FREEZE_INFORMATION,
                (&raw const info).cast(),
                u32::try_from(std::mem::size_of_val(&info)).unwrap(),
            )
        };
        if status == 0 { Ok(()) } else { Err(status) }
    }
}

/// The Windows version, as `10.0.<build>`.
pub(crate) fn windows_build() -> String {
    // SAFETY: zeroed is a valid value of the plain structure.
    let mut v: OsVersionInfo = unsafe { std::mem::zeroed() };
    v.size = u32::try_from(std::mem::size_of::<OsVersionInfo>()).unwrap();
    // SAFETY: a structure with its size set.
    if unsafe { RtlGetVersion(&mut v) } != 0 {
        return "of an unknown build".to_owned();
    }
    format!("{}.{}.{}", v.major, v.minor, v.build)
}

fn status(s: i32) -> String {
    format!("NTSTATUS {:#010X}", s.cast_unsigned())
}

// ------------------------------------------------------------- the self-check

/// Set in the self-check's throwaway process: the jailer then spins from its
/// C runtime's start, before `main` ([`SPIN`]).
const SPIN_ENV: &str = "WICK_JAILER_FREEZER_SPIN";
/// The handed-over directory handle ([`handover`]).
const HANDOVER_ENV: &str = "WICK_JAILER_FREEZER";

/// [`HANDOVER_ENV`] as the jailer started: upstream's jailer clears its
/// environment first thing, so it is read before `main`.
static HANDOVER_AT_START: std::sync::OnceLock<Option<std::ffi::OsString>> = std::sync::OnceLock::new();

extern "C" fn at_start() {
    if std::env::var_os(SPIN_ENV).is_some() {
        // The self-check's process: spin until it is ended.
        loop {
            std::hint::spin_loop();
        }
    }
    let _ = HANDOVER_AT_START.set(std::env::var_os(HANDOVER_ENV));
}

/// Runs [`at_start`] with the C runtime's initializers, before `main`.
#[used]
#[unsafe(link_section = ".CRT$XCU")]
static SPIN: extern "C" fn() = at_start;

/// A process's CPU time, in 100 ns units.
fn cpu_time(process: HANDLE) -> u64 {
    let (mut c, mut e, mut k, mut u) = (0u64, 0u64, 0u64, 0u64);
    // SAFETY: a process handle and four out-parameters (FILETIME is two u32s).
    unsafe { GetProcessTimes(process, (&raw mut c).cast(), (&raw mut e).cast(), (&raw mut k).cast(), (&raw mut u).cast()) };
    k + u
}

/// Proves that this host freezes a job: a throwaway process (this jailer's
/// binary spinning, [`SPIN_ENV`]) in a job of its own (no limits, so nothing
/// slows it), running, frozen, its CPU time standing still over 2 x 30 ms
/// (Windows counts CPU time in 15.6 ms ticks), thawed, running again, ended.
/// About 65 to 90 ms (measured on Windows Server 2022, the same check with
/// cmd.exe as the spinner). The error says what failed and the build.
pub(crate) fn self_check() -> Result<(), String> {
    let fail = |what: String| format!("{}: {what} (Windows {})", fv::CANNOT_WORK, windows_build());
    let exe = std::env::current_exe().map_err(|e| fail(format!("the jailer's binary: {e}")))?;
    let mut env: Vec<u16> = Vec::new();
    for var in [format!("{SPIN_ENV}=1"), format!("SystemRoot={}", std::env::var("SystemRoot").unwrap_or_default())] {
        env.extend(var.encode_utf16());
        env.push(0);
    }
    env.push(0);
    let mut cmd = wide(format!("\"{}\"", exe.display()));
    // SAFETY: plain data.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap();
    // SAFETY: plain data.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated application path, command line and environment.
    if unsafe {
        CreateProcessW(
            wide(&exe).as_ptr(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            env.as_ptr().cast(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    } == 0
    {
        return Err(fail(format!("starting a process to freeze: {}", last_error())));
    }
    // SAFETY: handles CreateProcess gave us.
    let (process, thread) = unsafe { (OwnedHandle::from_raw_handle(pi.hProcess), OwnedHandle::from_raw_handle(pi.hThread)) };
    let p = process.as_raw_handle();
    let result = (|| {
        let job = kill_on_close_job().map_err(|e| format!("a job: {e}"))?;
        // SAFETY: handles we own.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), p) } == 0 {
            return Err(format!("putting the process in a job: {}", last_error()));
        }
        // SAFETY: the suspended main thread.
        unsafe { ResumeThread(thread.as_raw_handle()) };
        let running = |since: u64| {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while cpu_time(p) == since {
                if std::time::Instant::now() > end {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            true
        };
        if !running(0) {
            return Err("the process to freeze did not run within 5 s".to_owned());
        }
        let mut j = Job(job.as_raw_handle());
        j.set(true).map_err(|s| format!("freezing a job: {}", status(s)))?;
        let tick = std::time::Duration::from_millis(30);
        std::thread::sleep(tick);
        let a = cpu_time(p);
        std::thread::sleep(tick);
        let b = cpu_time(p);
        if a != b {
            return Err(format!(
                "the job's freeze returned success, but its process used CPU time ({a} -> {b} x 100 ns in 30 ms)"
            ));
        }
        j.set(false).map_err(|s| format!("thawing a job: {}", status(s)))?;
        if !running(b) {
            return Err("the thawed job's process did not run again within 5 s".to_owned());
        }
        Ok(())
    })();
    // SAFETY: our child.
    unsafe {
        TerminateProcess(p, 1);
        WaitForSingleObject(p, 5000);
    }
    result.map_err(fail)
}

/// An unnamed job whose processes end with its last handle.
fn kill_on_close_job() -> io::Result<OwnedHandle> {
    // SAFETY: an unnamed job.
    let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if h.is_null() {
        return Err(last_error());
    }
    // SAFETY: a handle we own.
    let job = unsafe { OwnedHandle::from_raw_handle(h) };
    // SAFETY: plain data.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: a structure of the size passed.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&raw const info).cast(),
            u32::try_from(std::mem::size_of_val(&info)).unwrap(),
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(job)
}

// ------------------------------------------------------------- the files

/// The jail's freezer files, in the directory that holds them.
#[derive(Debug)]
pub(crate) struct Files {
    dir: PathBuf,
    version: Version,
    /// Who may own them: SYSTEM, the administrators, the operator.
    owners: [String; 3],
    /// The DACL they are made with.
    dacl: String,
}

/// A file the jailer looked at.
enum Opened {
    File(std::fs::File),
    /// Not there, or not a file the jailer trusts.
    Untrusted,
    /// Another process holds it and shares it with no one.
    Busy,
}

/// What a write of one of the files came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Written {
    Done,
    /// Another process holds the file without sharing writing: written
    /// once the settle timer fires again.
    Busy,
}

/// What writing the control file back came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Restored {
    Done,
    /// Another process holds the file without sharing writing: written
    /// once the settle timer fires again.
    Busy,
    /// A writer wrote the file after the jailer read it: what it holds,
    /// left as it is, to be handled as written.
    Changed(Vec<u8>),
}

fn is_busy(e: &io::Error) -> bool {
    matches!(e.raw_os_error().map(i32::cast_unsigned), Some(ERROR_SHARING_VIOLATION | ERROR_ACCESS_DENIED))
}

fn not_found(e: &io::Error) -> bool {
    matches!(e.raw_os_error().map(i32::cast_unsigned), Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND))
}

/// Deletes `path` (a NUL-terminated wide path) if it is there.
fn delete(path: &[u16]) -> io::Result<()> {
    // SAFETY: a NUL-terminated path.
    if unsafe { DeleteFileW(path.as_ptr()) } == 0 {
        let e = last_error();
        if !not_found(&e) {
            return Err(e);
        }
    }
    Ok(())
}

// The files are read and written as near as Windows lets a file be to a
// cgroup's on Linux, where any process opens them at any time, is never
// refused and reads a whole value. On Windows a handle that can write a
// file, or delete it (as replacing it by a rename does), refuses every
// opener that does not share that with it, and every way to change a
// file's content takes such a handle. Measured on Windows Server 2022 build
// 20348, four readers in tight loops, 2000 changes (agent-state/win2/
// results-fzs.txt, results-fzs2.txt, results-fzt.txt):
//
// - written in place: a reader that shares reading and writing (`type`,
//   Get-Content, C's fopen) is never refused; one that shares reading alone
//   (.NET's File.ReadAllText) is, about ten times a change; a value changed
//   in several bytes can be read half written ("THAWEN\n", twice);
// - replaced by a rename (MoveFileExW, or a POSIX-semantics rename) of a
//   file written aside: every reader that does not share deleting, both of
//   those, is refused about twice a change, whoever scans the files (the
//   same with the files written 10 s before); a reader holding the file
//   refuses the rename itself;
// - a hard link made and removed: no reader refused.
//
// So the jailer makes a file by writing it aside and linking the name to
// it, where nothing is (a reader finds no file, then the whole file), and
// writes one in place, never cutting it first: what it writes into a file
// differs from what the file holds in one byte (cgroup.events, cgroup.freeze)
// or only in its end (a value of freezer.state written back canonical keeps
// its word), so it is never read half written, but for an invalid value
// written over. A reader that shares writing is never refused
// (`test_readers_are_never_refused_v1`, `_v2`); one that shares reading
// alone can be, while the jailer writes (on Linux, never): a Windows file
// cannot keep it from that (CreateFileW: a share mode that conflicts with
// the access of an open handle fails with ERROR_SHARING_VIOLATION).
impl Files {
    fn new(dir: &Path, version: Version) -> io::Result<Files> {
        let user = super::user_sid()?;
        Ok(Files {
            dir: plain(dir),
            version,
            dacl: format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user})"),
            owners: ["S-1-5-18".to_owned(), "S-1-5-32-544".to_owned(), user],
        })
    }

    /// Makes the files in `dir` for a jail in `state`. Fails if one is there
    /// already: the jailer never takes over files it did not make.
    pub(crate) fn create(dir: &Path, version: Version, state: State) -> io::Result<Files> {
        let files = Files::new(dir, version)?;
        files.make(version.control(), version.canonical(state))?;
        if version == Version::V2 {
            files.make(fv::EVENTS, &fv::events(true, state == State::Frozen))?;
        }
        Ok(files)
    }

    /// The files another jailer made in `dir` and handed over ([`handover`]).
    fn adopt(dir: &Path, version: Version) -> io::Result<Files> {
        let files = Files::new(dir, version)?;
        if !matches!(files.open_trusted(version.control(), false)?, Opened::File(_)) {
            return Err(io::Error::other(format!(
                "{}: not the file the jailer that handed it over made",
                files.path(version.control()).display()
            )));
        }
        Ok(files)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// `name`, made with `content` and the files' DACL (never one that is
    /// there): written as `.<name>.tmp`, which no one but the jailer opens,
    /// then given the name, so it is whole from the moment it is there.
    fn make(&self, name: &str, content: &[u8]) -> io::Result<()> {
        let path = self.path(name);
        let tmp_path = self.path(&format!(".{name}.tmp"));
        let fail = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", path.display()));
        let tmp = wide(&tmp_path);
        delete(&tmp).map_err(fail)?;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: a NUL-terminated SDDL string and an out-pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(&self.dacl).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(fail(last_error()));
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        // SAFETY: a NUL-terminated path; the descriptor outlives the call.
        let h = unsafe {
            CreateFileW(tmp.as_ptr(), GENERIC_WRITE, 0, &sa, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, std::ptr::null_mut())
        };
        let err = last_error();
        // SAFETY: allocated by the conversion.
        unsafe { LocalFree(sd) };
        if h == INVALID_HANDLE_VALUE {
            return Err(fail(err));
        }
        // SAFETY: a handle we own.
        let mut file = unsafe { std::fs::File::from_raw_handle(h) };
        let written = file.write_all(content);
        drop(file);
        // SAFETY: NUL-terminated paths. The name is linked to the file, not
        // moved: a move holds the file with delete access while it is
        // named, which refused a reader sharing reading and writing that
        // opened it then (`test_readers_are_never_refused_v1`, 4 times in
        // a run); a link made and the other name removed refuse no reader
        // (agent-state/win2/results-fzs.txt). Fails if the name is there.
        let linked = written.and_then(|()| {
            if unsafe { CreateHardLinkW(wide(&path).as_ptr(), tmp.as_ptr(), std::ptr::null()) } == 0 {
                Err(last_error())
            } else {
                Ok(())
            }
        });
        let removed = delete(&tmp);
        linked.and(removed).map_err(fail)
    }

    /// `name`, open (for writing when `write`), if it is a file the jailer
    /// trusts: a regular file, not a reparse point, with one name, owned by
    /// SYSTEM, the administrators or the operator. To read, shared with
    /// every other opener; to write, with every opener but a writer, so
    /// that the jailer's write is never made over another's
    /// ([`restore`](Self::restore)). An opener that does not share what this
    /// asks makes it [`Opened::Busy`].
    fn open_trusted(&self, name: &str, write: bool) -> io::Result<Opened> {
        use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
        let access = if write { GENERIC_WRITE | GENERIC_READ } else { GENERIC_READ } | READ_CONTROL | FILE_READ_ATTRIBUTES;
        let share = if write { FILE_SHARE_READ | FILE_SHARE_DELETE } else { FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE };
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .access_mode(access)
            .share_mode(share)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path(name))
        {
            Ok(f) => f,
            // Not there; a directory (opened only with backup semantics) or
            // a file whose DACL refuses the jailer: not one it made.
            Err(e) if not_found(&e) || e.raw_os_error().map(i32::cast_unsigned) == Some(ERROR_ACCESS_DENIED) => {
                return Ok(Opened::Untrusted);
            }
            Err(e) if e.raw_os_error().map(i32::cast_unsigned) == Some(ERROR_SHARING_VIOLATION) => {
                return Ok(Opened::Busy);
            }
            Err(e) => return Err(e),
        };
        // SAFETY: zeroed is a valid value of the plain structure.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: an open handle and a structure to fill.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(last_error());
        }
        if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
            || info.nNumberOfLinks != 1
        {
            return Ok(Opened::Untrusted);
        }
        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: an open handle with READ_CONTROL; out-pointers.
        let rc = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
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
        let owner = super::sid_string(owner);
        // SAFETY: allocated by GetSecurityInfo; `owner` points into it and is
        // no longer used.
        unsafe { LocalFree(sd) };
        Ok(if self.owners.contains(&owner?) { Opened::File(file) } else { Opened::Untrusted })
    }

    /// Reads the control file: the request, whether the file holds the
    /// request's canonical form, and what it holds (what
    /// [`restore`](Self::restore) is given); `None` while another process
    /// holds it unshared.
    pub(crate) fn read(&self) -> io::Result<Option<(fv::Request, bool, Vec<u8>)>> {
        let file = match self.open_trusted(self.version.control(), false)? {
            Opened::File(file) => file,
            Opened::Untrusted => return Ok(Some((fv::Request::Invalid, false, Vec::new()))),
            Opened::Busy => return Ok(None),
        };
        let mut buf = Vec::with_capacity(fv::MAX_FILE + 1);
        file.take(u64::try_from(fv::MAX_FILE + 1).unwrap()).read_to_end(&mut buf)?;
        let request = fv::parse(self.version, &buf);
        let canonical = matches!(request, fv::Request::Set(s) if buf == self.version.canonical(s));
        Ok(Some((request, canonical, buf)))
    }

    /// Writes the control file back to `state`, in place (a writer that has
    /// it open writes to the same file), unless a writer wrote it after the
    /// jailer read `seen` from it: then [`Restored::Changed`] with what it
    /// holds, which is left as it is. What it holds is read through the
    /// handle that writes it, which shares no writing, so no write lands
    /// between that read and the jailer's write: none is lost (on Linux a
    /// write is never undone either). A writer opening it meanwhile is
    /// refused; one that has it open makes it [`Restored::Busy`]. One that
    /// is not a trusted file is removed (a link, not what it names) and
    /// made again.
    pub(crate) fn restore(&self, state: State, seen: &[u8]) -> io::Result<Restored> {
        self.write_over(self.version.control(), self.version.canonical(state), Some(seen))
    }

    /// v2: `cgroup.events`, written in place: from one state to another one
    /// byte changes, so a reader never sees half of it. A reader that holds
    /// it without sharing writing makes it [`Written::Busy`].
    pub(crate) fn write_events(&self, populated: bool, frozen: bool) -> io::Result<Written> {
        if self.version != Version::V2 {
            return Ok(Written::Done);
        }
        // Not compared with what it held: Changed is never returned so.
        Ok(match self.write_over(fv::EVENTS, &fv::events(populated, frozen), None)? {
            Restored::Busy => Written::Busy,
            Restored::Done | Restored::Changed(_) => Written::Done,
        })
    }

    /// Writes `content` into `name` in place, from its start, then cuts it
    /// after it (never cut first: a reader would find it empty); if `seen`,
    /// only while it holds that.
    fn write_over(&self, name: &str, content: &[u8], seen: Option<&[u8]>) -> io::Result<Restored> {
        match self.open_trusted(name, true)? {
            Opened::Busy => Ok(Restored::Busy),
            Opened::File(mut file) => {
                if let Some(seen) = seen {
                    let mut was = Vec::with_capacity(fv::MAX_FILE + 1);
                    (&file).take(u64::try_from(fv::MAX_FILE + 1).unwrap()).read_to_end(&mut was)?;
                    if was != seen {
                        return Ok(Restored::Changed(was));
                    }
                    file.rewind()?;
                }
                file.write_all(content)?;
                file.set_len(u64::try_from(content.len()).unwrap())?;
                Ok(Restored::Done)
            }
            Opened::Untrusted => {
                let path = wide(self.path(name));
                // SAFETY: a NUL-terminated path. A file, else a directory or
                // junction; neither follows a reparse point.
                if unsafe { DeleteFileW(path.as_ptr()) } == 0 {
                    let e = last_error();
                    // SAFETY: as above.
                    if !not_found(&e) && unsafe { RemoveDirectoryW(path.as_ptr()) } == 0 {
                        return if is_busy(&e) { Ok(Restored::Busy) } else { Err(e) };
                    }
                }
                match self.make(name, content) {
                    Ok(()) => Ok(Restored::Done),
                    Err(e) if is_busy(&e) => Ok(Restored::Busy),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

// ------------------------------------------------------------- the watch

/// A change notification on the files' directory and the settle timer.
pub(crate) struct Watch {
    change: HANDLE,
    timer: OwnedHandle,
    settling: bool,
}

/// What woke the jailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    /// Something in the directory changed (or the first look).
    File,
    /// The settle timer fired.
    Settled,
}

impl Watch {
    pub(crate) fn new(files: &Files) -> io::Result<Watch> {
        // SAFETY: a NUL-terminated path.
        let change = unsafe {
            FindFirstChangeNotificationW(
                wide(&files.dir).as_ptr(),
                0,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_ATTRIBUTES
                    | FILE_NOTIFY_CHANGE_SECURITY,
            )
        };
        if change == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        // SAFETY: an unnamed auto-reset timer.
        let timer = unsafe { CreateWaitableTimerW(std::ptr::null(), 0, std::ptr::null()) };
        if timer.is_null() {
            let e = last_error();
            // SAFETY: the notification handle just made.
            unsafe { FindCloseChangeNotification(change) };
            return Err(e);
        }
        // SAFETY: a handle we own.
        Ok(Watch { change, timer: unsafe { OwnedHandle::from_raw_handle(timer) }, settling: false })
    }

    /// The handles to wait on: the change notification, then the timer.
    pub(crate) fn handles(&self) -> [HANDLE; 2] {
        [self.change, self.timer.as_raw_handle()]
    }

    /// Asks for the next change; done before the files are read, so a write
    /// made after the read is never missed.
    fn rearm(&self) -> io::Result<()> {
        // SAFETY: our notification handle.
        if unsafe { FindNextChangeNotification(self.change) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    fn settle_later(&mut self) -> io::Result<()> {
        let due = -i64::from(fv::SETTLE_MS) * 10_000;
        // SAFETY: our timer; a relative due time.
        if unsafe { SetWaitableTimer(self.timer.as_raw_handle(), &due, 0, None, std::ptr::null(), 0) } == 0 {
            return Err(last_error());
        }
        self.settling = true;
        Ok(())
    }

    fn settle_cancel(&mut self) {
        // SAFETY: our timer.
        unsafe { CancelWaitableTimer(self.timer.as_raw_handle()) };
        self.settling = false;
    }

    /// Waits for the next event (`None`: forever).
    pub(crate) fn wait(&self, timeout_ms: Option<u32>) -> io::Result<Option<Event>> {
        use windows_sys::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};
        let hs = self.handles();
        // SAFETY: two handles we own.
        let r = unsafe { WaitForMultipleObjects(2, hs.as_ptr(), 0, timeout_ms.unwrap_or(INFINITE)) };
        match r {
            WAIT_OBJECT_0 => Ok(Some(Event::File)),
            r if r == WAIT_OBJECT_0 + 1 => Ok(Some(Event::Settled)),
            windows_sys::Win32::Foundation::WAIT_TIMEOUT => Ok(None),
            _ => Err(last_error()),
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // SAFETY: our notification handle.
        unsafe { FindCloseChangeNotification(self.change) };
    }
}

// ------------------------------------------------------------- the protocol

/// The control file's side, shared by the jailer waiting at the cgroup step
/// and the jailer keeping a running jail's files.
pub(crate) struct Control {
    /// The state the jail is in (or is being put in).
    pub(crate) state: State,
    /// The control file still to be restored (busy when last tried).
    restore_pending: bool,
}

impl Control {
    pub(crate) fn new(state: State) -> Control {
        Control { state, restore_pending: false }
    }

    /// Handles `event`: the state the file now asks for (`None`: nothing to
    /// do). Logs to `log` what it restores.
    pub(crate) fn handle(
        &mut self,
        files: &Files,
        watch: &mut Watch,
        event: Event,
        log: &mut dyn FnMut(&str),
    ) -> io::Result<Option<State>> {
        if event == Event::File {
            watch.rearm()?;
        } else {
            watch.settling = false;
        }
        let Some((request, canonical, seen)) = files.read()? else {
            // Held unshared by its writer: looked at again after the settle.
            if !watch.settling {
                watch.settle_later()?;
            }
            return Ok(None);
        };
        match request {
            fv::Request::Set(state) => {
                if watch.settling {
                    watch.settle_cancel();
                }
                self.restore_pending = false;
                self.state = state;
                // As Linux reads the file back; nothing written when it
                // holds that already.
                if !canonical {
                    self.write_back(files, watch, &seen)?;
                }
                Ok(Some(state))
            }
            fv::Request::Empty | fv::Request::Invalid if event == Event::Settled || self.restore_pending => {
                if !self.restore_pending {
                    log(&fv::ignored(files.version, request));
                }
                self.write_back(files, watch, &seen)?;
                Ok(None)
            }
            fv::Request::Empty | fv::Request::Invalid => {
                if !watch.settling {
                    watch.settle_later()?;
                }
                Ok(None)
            }
        }
    }

    /// Writes the control file back to the state, `seen` being what the
    /// jailer read from it. Held by a writer: pending, written after the
    /// settle, the file meanwhile holding what the writer wrote. Written
    /// after the jailer read it: left as the writer left it, and handled as
    /// any write, which the change notification reports (the watch was
    /// armed before the read), so no write is undone.
    fn write_back(&mut self, files: &Files, watch: &mut Watch, seen: &[u8]) -> io::Result<()> {
        match files.restore(self.state, seen)? {
            Restored::Done | Restored::Changed(_) => self.restore_pending = false,
            Restored::Busy => {
                self.restore_pending = true;
                watch.settle_later()?;
            }
        }
        Ok(())
    }
}

/// Why the jailer kills a jail.
#[derive(Debug)]
pub(crate) enum Failure {
    Freeze(bool, i32),
    Files(&'static str, io::Error),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Freeze(on, s) => write!(f, "{} the job: {}", if *on { "freezing" } else { "thawing" }, status(*s)),
            Failure::Files(what, e) => write!(f, "{what}: {e}"),
        }
    }
}

/// Where the jail is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Its processes are made, suspended, not yet resumed.
    Starting,
    Running,
    /// Firecracker has exited: what is left ends with it; a request is
    /// shown, not applied (Linux's cgroup holds nothing of Firecracker's).
    Ending,
}

/// The freezer of a jail the jailer runs: the files, the watch and the
/// job's state, which only this changes.
pub(crate) struct Freezer {
    files: Files,
    watch: Watch,
    control: Control,
    phase: Phase,
    /// Whether the job is frozen.
    frozen: bool,
    /// What `cgroup.events` says.
    shown: Option<(bool, bool)>,
    events_pending: bool,
}

impl Freezer {
    /// The freezer of the jail whose directory (`<id>`, next to `root`) is
    /// `jail_dir`: the files the cgroup step made, or new ones.
    pub(crate) fn for_exec(jail_dir: &Path) -> Result<Freezer, String> {
        let jail_dir = plain(jail_dir);
        let files = match FILES.lock().unwrap().take() {
            Some(files) if files.dir == jail_dir => files,
            Some(files) => {
                return Err(format!(
                    "the freezer files are in {}, the jail in {}",
                    files.dir.display(),
                    jail_dir.display()
                ));
            }
            None => Files::create(&jail_dir, version(), State::Thawed).map_err(|e| e.to_string())?,
        };
        Freezer::of(files)
    }

    /// The freezer of `files`.
    fn of(files: Files) -> Result<Freezer, String> {
        let watch = Watch::new(&files).map_err(|e| format!("watching {}: {e}", files.dir.display()))?;
        Ok(Freezer {
            files,
            watch,
            control: Control::new(State::Thawed),
            phase: Phase::Starting,
            frozen: false,
            shown: None,
            events_pending: false,
        })
    }

    /// The handles the jailer waits on besides Firecracker.
    pub(crate) fn handles(&self) -> [HANDLE; 2] {
        self.watch.handles()
    }

    fn log(&self, line: &str) {
        eprintln!("jailer: freezer of {}: {line}", self.files.dir.display());
    }

    /// `cgroup.events`: populated until the job is closed; frozen while the
    /// job is, and after Firecracker's exit as the file asks.
    fn show(&mut self) -> Result<(), Failure> {
        let frozen = self.frozen || (self.phase == Phase::Ending && self.control.state == State::Frozen);
        let now = (true, frozen);
        if self.shown == Some(now) && !self.events_pending {
            return Ok(());
        }
        match self.files.write_events(now.0, now.1).map_err(|e| Failure::Files("writing cgroup.events", e))? {
            Written::Done => {
                self.shown = Some(now);
                self.events_pending = false;
            }
            Written::Busy => {
                self.events_pending = true;
                self.watch.settle_later().map_err(|e| Failure::Files("the settle timer", e))?;
            }
        }
        Ok(())
    }

    fn apply(&mut self, job: &mut dyn JobFreeze, state: State) -> Result<(), Failure> {
        let want = state == State::Frozen;
        if self.phase == Phase::Ending || self.frozen == want {
            return Ok(());
        }
        job.set(want).map_err(|s| Failure::Freeze(want, s))?;
        self.frozen = want;
        Ok(())
    }

    /// Before the jail's processes are resumed: frozen now if the file says
    /// so (a process resumed in a frozen job does not run).
    pub(crate) fn before_resume(&mut self, job: &mut dyn JobFreeze) -> Result<(), Failure> {
        self.step(job, Event::File)?;
        self.phase = Phase::Running;
        self.apply(job, self.control.state)?;
        self.show()
    }

    /// Handles what woke the jailer: `which` is the index in [`handles`](Self::handles).
    pub(crate) fn woken(&mut self, job: &mut dyn JobFreeze, which: usize) -> Result<(), Failure> {
        self.step(job, if which == 0 { Event::File } else { Event::Settled })
    }

    fn step(&mut self, job: &mut dyn JobFreeze, event: Event) -> Result<(), Failure> {
        let dir = self.files.dir.display().to_string();
        let mut log = |line: &str| eprintln!("jailer: freezer of {dir}: {line}");
        let wanted = self
            .control
            .handle(&self.files, &mut self.watch, event, &mut log)
            .map_err(|e| Failure::Files("reading the control file", e))?;
        if let Some(state) = wanted
            && self.phase == Phase::Running
        {
            self.apply(job, state)?;
        }
        if self.phase != Phase::Starting {
            self.show()?;
        }
        Ok(())
    }

    /// Firecracker has exited: the rest of the jail (the API process) must
    /// run to end with it, as without the freezer.
    pub(crate) fn firecracker_exited(&mut self, job: &mut dyn JobFreeze) -> Result<(), Failure> {
        if self.frozen {
            job.set(false).map_err(|s| Failure::Freeze(false, s))?;
            self.frozen = false;
        }
        self.phase = Phase::Ending;
        Ok(())
    }

    /// The jail is empty (its job closed): `populated 0`.
    pub(crate) fn emptied(&mut self) {
        let frozen = self.control.state == State::Frozen;
        if let Err(e) = self.files.write_events(false, frozen) {
            self.log(&format!("writing cgroup.events: {e}"));
        }
    }

    /// Logs why the jail is killed.
    pub(crate) fn killed(&self, failure: &Failure) {
        self.log(&format!("{failure}: {}", fv::KILLED));
    }
}

// ------------------------------------------------------------- the cgroup step and the hand-over

/// The files the jailer made or took over at the cgroup step, for the exec.
static FILES: Mutex<Option<Files>> = Mutex::new(None);
/// The cgroup version of the jail: the builder's, else upstream's default.
static VERSION: Mutex<Option<Version>> = Mutex::new(None);

pub(crate) fn set_version(v: Version) {
    *VERSION.lock().unwrap() = Some(v);
}

fn version() -> Version {
    VERSION.lock().unwrap().unwrap_or(Version::V1)
}

/// A file's volume and index: what a handle and a path are compared by.
fn identity(file: &std::fs::File) -> io::Result<(u32, u64)> {
    // SAFETY: zeroed is a valid value of the plain structure.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: an open handle and a structure to fill.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(last_error());
    }
    Ok((info.dwVolumeSerialNumber, (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)))
}

fn open_dir(dir: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)
}

/// The directory handle a jailer started again by `--daemonize` or
/// `--new-pid-ns` was handed, if it names `dir`.
fn handed_over(dir: &Path) -> io::Result<Option<()>> {
    let Some(value) = HANDOVER_AT_START.get().cloned().flatten() else {
        return Ok(None);
    };
    let handle: usize = value
        .to_str()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| io::Error::other(format!("{HANDOVER_ENV} is not a handle value: {}", value.to_string_lossy())))?;
    // SAFETY: the handle the jailer that started this one passed. Not closed
    // unless it is the one asked for: a value that names another handle of
    // this process must not close it.
    let handed = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(handle as HANDLE) });
    let ours = open_dir(dir)?;
    match (identity(&handed), identity(&ours)) {
        (Ok(a), Ok(b)) if a == b => {
            drop(std::mem::ManuallyDrop::into_inner(handed));
            Ok(Some(()))
        }
        _ => Err(io::Error::other(format!(
            "{HANDOVER_ENV} names no handle to {}: the freezer files were not handed over",
            dir.display()
        ))),
    }
}

/// `--cgroup freezer.state=<state>` (v1), at the cgroup step: the files now
/// (or those handed over) and, while they say `FROZEN`, the jailer waits
/// here, as on Linux the jailer freezes itself at this step.
pub(crate) fn at_cgroup_step(dir: &Path, state: State) -> io::Result<()> {
    let dir = plain(dir);
    let files = match handed_over(&dir)? {
        Some(()) => Files::adopt(&dir, Version::V1)?,
        None => Files::create(&dir, Version::V1, state)?,
    };
    let mut watch = Watch::new(&files)?;
    let mut control = Control::new(state);
    let mut log = |line: &str| eprintln!("jailer: freezer of {}: {line}", dir.display());
    let mut event = Event::File;
    loop {
        control.handle(&files, &mut watch, event, &mut log)?;
        if control.state == State::Thawed && !watch.settling {
            break;
        }
        event = watch.wait(None)?.unwrap_or(Event::File);
    }
    *FILES.lock().unwrap() = Some(files);
    Ok(())
}

/// For a jailer about to start itself again (`--daemonize`, `--new-pid-ns`)
/// after the cgroup step made the files: the handle the new jailer gets
/// (inheritable) and finds in [`HANDOVER_ENV`], so it takes them over.
pub(crate) fn handover() -> io::Result<Option<OwnedHandle>> {
    let Some(dir) = FILES.lock().unwrap().as_ref().map(|f| f.dir.clone()) else {
        return Ok(None);
    };
    let file = open_dir(&dir)?;
    let h = OwnedHandle::from(file);
    // SAFETY: a handle we own.
    if unsafe { SetHandleInformation(h.as_raw_handle(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        return Err(last_error());
    }
    // SAFETY: the jailer is single-threaded until the jail is built.
    unsafe { std::env::set_var(HANDOVER_ENV, (h.as_raw_handle() as usize).to_string()) };
    Ok(Some(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The layout System Informer gives (16 bytes, `Freeze` at 4).
    #[test]
    fn test_freeze_information_layout() {
        assert_eq!(std::mem::size_of::<JobObjectFreezeInformation>(), 16);
        let info = JobObjectFreezeInformation { flags: FREEZE_OPERATION, freeze: 1, ..Default::default() };
        // SAFETY: a plain structure, read as its bytes.
        let bytes: [u8; 16] = unsafe { std::mem::transmute(info) };
        assert_eq!(bytes, [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wick-freezer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn content(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    /// The request and whether it is canonical.
    fn request(files: &Files) -> (fv::Request, bool) {
        let (request, canonical, _) = files.read().unwrap().unwrap();
        (request, canonical)
    }

    /// Reads `path` as `type` and Get-Content open it, sharing reading and
    /// writing.
    fn read_sharing(path: &Path) -> String {
        let mut s = String::new();
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        s
    }

    /// Restores the control file after reading it.
    fn restore(files: &Files, state: State) -> Restored {
        let (_, _, seen) = files.read().unwrap().unwrap();
        files.restore(state, &seen).unwrap()
    }

    // The files: made exclusive, with their DACL; read back; restored; a
    // write that came after the read is not lost; a hard link or a
    // directory in the control file's place is not trusted, and is replaced.
    #[test]
    fn test_files() {
        let dir = temp_dir("files");
        let files = Files::create(&dir, Version::V2, State::Thawed).unwrap();
        assert_eq!(content(&dir.join("cgroup.freeze")), "0\n");
        assert_eq!(content(&dir.join("cgroup.events")), "populated 1\nfrozen 0\n");
        assert!(Files::create(&dir, Version::V2, State::Thawed).is_err(), "made over existing files");
        assert_eq!(request(&files), (fv::Request::Set(State::Thawed), true));
        std::fs::write(dir.join("cgroup.freeze"), "1").unwrap();
        assert_eq!(request(&files), (fv::Request::Set(State::Frozen), false));
        assert_eq!(restore(&files, State::Frozen), Restored::Done);
        assert_eq!(content(&dir.join("cgroup.freeze")), "1\n");
        // Written after the read: left as written, and what it holds comes
        // back.
        std::fs::write(dir.join("cgroup.freeze"), "1").unwrap();
        let (_, _, seen) = files.read().unwrap().unwrap();
        std::fs::write(dir.join("cgroup.freeze"), "0").unwrap();
        assert_eq!(files.restore(State::Frozen, &seen).unwrap(), Restored::Changed(b"0".to_vec()));
        assert_eq!(content(&dir.join("cgroup.freeze")), "0");
        assert!(!dir.join(".cgroup.freeze.tmp").exists() && !dir.join(".cgroup.events.tmp").exists());
        assert_eq!(files.write_events(true, true).unwrap(), Written::Done);
        assert_eq!(content(&dir.join("cgroup.events")), "populated 1\nfrozen 1\n");
        // A hard link in its place.
        std::fs::remove_file(dir.join("cgroup.freeze")).unwrap();
        std::fs::write(dir.join("other"), "0\n").unwrap();
        std::fs::hard_link(dir.join("other"), dir.join("cgroup.freeze")).unwrap();
        assert_eq!(request(&files), (fv::Request::Invalid, false));
        assert_eq!(restore(&files, State::Frozen), Restored::Done);
        assert_eq!(content(&dir.join("cgroup.freeze")), "1\n");
        assert_eq!(content(&dir.join("other")), "0\n", "the link's other name was written");
        // A directory in its place.
        std::fs::remove_file(dir.join("cgroup.freeze")).unwrap();
        std::fs::create_dir(dir.join("cgroup.freeze")).unwrap();
        assert_eq!(request(&files), (fv::Request::Invalid, false));
        assert_eq!(restore(&files, State::Thawed), Restored::Done);
        assert_eq!(content(&dir.join("cgroup.freeze")), "0\n");
        // A reader that holds cgroup.events sharing reading alone: busy,
        // a reader that shares writing reads the state before (the old
        // truth, never a third thing) meanwhile; then done.
        let reader = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(dir.join("cgroup.events")).unwrap();
        assert_eq!(files.write_events(true, false).unwrap(), Written::Busy);
        assert_eq!(read_sharing(&dir.join("cgroup.events")), "populated 1\nfrozen 1\n");
        drop(reader);
        assert_eq!(files.write_events(true, false).unwrap(), Written::Done);
        assert_eq!(content(&dir.join("cgroup.events")), "populated 1\nfrozen 0\n");
        // One that holds it sharing writing: written under it, and it reads
        // the new state from the start again, as a reader polling it on
        // Linux does.
        let mut holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(dir.join("cgroup.events"))
            .unwrap();
        assert_eq!(files.write_events(true, true).unwrap(), Written::Done);
        let mut s = String::new();
        holder.read_to_string(&mut s).unwrap();
        assert_eq!(s, "populated 1\nfrozen 1\n");
        drop(holder);
        // The control file held so: what the writer wrote (the truth, in
        // its form) until written back.
        std::fs::write(dir.join("cgroup.freeze"), "1").unwrap();
        let reader = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(dir.join("cgroup.freeze")).unwrap();
        assert_eq!(restore(&files, State::Frozen), Restored::Busy);
        assert_eq!(read_sharing(&dir.join("cgroup.freeze")), "1");
        drop(reader);
        assert_eq!(restore(&files, State::Frozen), Restored::Done);
        assert_eq!(content(&dir.join("cgroup.freeze")), "1\n");
        std::fs::write(dir.join("cgroup.freeze"), "0\n").unwrap();
        // A writer that shares the control file with no one: busy, then read.
        let writer = std::fs::OpenOptions::new().write(true).share_mode(0).open(dir.join("cgroup.freeze")).unwrap();
        assert_eq!(files.read().unwrap(), None);
        assert_eq!(files.restore(State::Frozen, b"0\n").unwrap(), Restored::Busy);
        drop(writer);
        assert_eq!(request(&files), (fv::Request::Set(State::Thawed), true));
        // A writer that holds it open, sharing everything: not replaced
        // under it, so its next write is the file's.
        let mut writer = std::fs::OpenOptions::new().write(true).open(dir.join("cgroup.freeze")).unwrap();
        assert_eq!(files.restore(State::Frozen, b"0\n").unwrap(), Restored::Busy);
        writer.write_all(b"1").unwrap();
        drop(writer);
        assert_eq!(request(&files), (fv::Request::Set(State::Frozen), true));
        // v1: one file.
        let d1 = temp_dir("files-v1");
        Files::create(&d1, Version::V1, State::Frozen).unwrap();
        assert_eq!(content(&d1.join("freezer.state")), "FROZEN\n");
        assert!(!d1.join("cgroup.events").exists());
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(d1).unwrap();
    }

    /// Records the job calls.
    #[derive(Default)]
    struct FakeJob(Vec<bool>, bool);

    impl JobFreeze for FakeJob {
        fn set(&mut self, frozen: bool) -> Result<(), i32> {
            self.0.push(frozen);
            // As the measured job: a second freeze or thaw is refused.
            if self.1 == frozen {
                return Err(0xC000_000Du32.cast_signed());
            }
            self.1 = frozen;
            Ok(())
        }
    }

    fn write(dir: &Path, name: &str, s: &str) {
        std::fs::write(dir.join(name), s).unwrap();
    }

    /// Serves `freezer` until no event comes for 600 ms (past the settle).
    fn drain(freezer: &mut Freezer, job: &mut FakeJob) {
        while let Some(ev) = freezer.watch.wait(Some(600)).unwrap() {
            freezer.woken(job, usize::from(ev == Event::Settled)).unwrap();
        }
    }

    // The protocol on a real change notification: frozen before the resume
    // when the file says so; each write applied once (writing the state
    // again makes no second freeze, which the job would refuse); an invalid
    // write ignored and the file restored after the settle; a value in
    // another form rewritten canonical; cgroup.events follows; Firecracker's
    // exit thaws what is left.
    #[test]
    fn test_protocol() {
        let dir = temp_dir("protocol");
        set_version(Version::V2);
        let mut freezer = Freezer::for_exec(&dir).unwrap();
        let mut job = FakeJob::default();
        write(&dir, "cgroup.freeze", "1\n");
        freezer.before_resume(&mut job).unwrap();
        assert_eq!(job.0, [true]);
        assert_eq!(content(&dir.join("cgroup.events")), "populated 1\nfrozen 1\n");
        write(&dir, "cgroup.freeze", "1\n");
        drain(&mut freezer, &mut job);
        assert_eq!(job.0, [true], "the same state again froze again");
        write(&dir, "cgroup.freeze", "2\n");
        drain(&mut freezer, &mut job);
        assert_eq!(content(&dir.join("cgroup.freeze")), "1\n", "an invalid value was not restored");
        assert_eq!(job.0, [true]);
        write(&dir, "cgroup.freeze", " 0x0 ");
        drain(&mut freezer, &mut job);
        assert_eq!(content(&dir.join("cgroup.freeze")), "0\n");
        assert_eq!(content(&dir.join("cgroup.events")), "populated 1\nfrozen 0\n");
        assert_eq!(job.0, [true, false]);
        write(&dir, "cgroup.freeze", "1");
        drain(&mut freezer, &mut job);
        assert_eq!(job.0, [true, false, true]);
        freezer.firecracker_exited(&mut job).unwrap();
        assert_eq!(job.0, [true, false, true, false]);
        write(&dir, "cgroup.freeze", "0");
        drain(&mut freezer, &mut job);
        assert_eq!(job.0, [true, false, true, false], "a request after Firecracker's exit was applied");
        freezer.emptied();
        assert_eq!(content(&dir.join("cgroup.events")), "populated 0\nfrozen 0\n");
        drop(freezer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The job, shared with the thread that writes the control file.
    struct SharedJob(std::sync::Arc<Mutex<FakeJob>>);

    impl JobFreeze for SharedJob {
        fn set(&mut self, frozen: bool) -> Result<(), i32> {
            self.0.lock().unwrap().set(frozen)
        }
    }

    /// What a reader of a file saw: the reads, the reads refused, and what
    /// it read that is not one of the file's whole values.
    #[derive(Default, Debug)]
    struct Seen {
        share: u32,
        reads: u64,
        refused: u64,
        first_refusals: Vec<String>,
        torn: Vec<String>,
    }

    /// Reads `path`, opened sharing `share`, until `stop`, as fast as it
    /// can, each open and read under `gate`'s read side. Not there yet is no
    /// refusal; gone once it was there is.
    fn hammer(
        path: PathBuf,
        share: u32,
        whole: &'static [&'static str],
        gate: std::sync::Arc<std::sync::RwLock<()>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Seen {
        let mut seen = Seen { share, ..Seen::default() };
        let mut was_there = false;
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            let _gate = gate.read().unwrap();
            match std::fs::OpenOptions::new().read(true).share_mode(share).open(&path) {
                Ok(mut f) => {
                    was_there = true;
                    let mut s = String::new();
                    f.read_to_string(&mut s).unwrap();
                    seen.reads += 1;
                    if !whole.contains(&s.as_str()) && seen.torn.len() < 10 {
                        seen.torn.push(s);
                    }
                }
                Err(e) if not_found(&e) && !was_there => {}
                Err(e) => {
                    seen.refused += 1;
                    if seen.first_refusals.len() < 3 {
                        seen.first_refusals.push(format!("{}{e}", if was_there { "" } else { "before the first read: " }));
                    }
                }
            }
        }
        seen
    }

    /// Writes `value` into the control file in place as a writer that
    /// keeps the file (`echo 1 >`) does, without cutting it first, under
    /// `gate`'s write side; opened again while the jailer's write-back
    /// holds it (which shares no writing): the number of times.
    fn write_over(path: &Path, value: &str, gate: &std::sync::RwLock<()>) -> u64 {
        let mut refused = 0;
        loop {
            let _gate = gate.write().unwrap();
            match std::fs::OpenOptions::new().write(true).open(path) {
                Ok(mut f) => {
                    f.write_all(value.as_bytes()).unwrap();
                    f.set_len(u64::try_from(value.len()).unwrap()).unwrap();
                    return refused;
                }
                Err(e) if e.raw_os_error().map(i32::cast_unsigned) == Some(ERROR_SHARING_VIOLATION) => refused += 1,
                Err(e) => panic!("writing {}: {e}", path.display()),
            }
        }
    }

    // As a cgroup's files on Linux, which a reader opens and reads whatever
    // the kernel does meanwhile. Readers of both files in tight loops from
    // before the jailer makes them, while the state flips 1000 times,
    // written in a form the jailer writes back canonical each time:
    //
    // - those that open as `type`, Get-Content, Python's open and C's fopen
    //   do (sharing reading and writing) are never refused and never read
    //   anything but a whole value (neither half of one nor an empty file);
    // - those that open as .NET's File.ReadAllText and File.OpenRead do
    //   (sharing reading alone) are counted, not held to zero: Windows
    //   refuses them while any handle can write the file (CreateFileW: "You
    //   cannot request a sharing mode that conflicts with the access mode
    //   that is specified in an existing request that has an open handle"),
    //   and every way to change a file's content takes one (measured,
    //   agent-state/win2/results-fzs.txt, results-fzs2.txt,
    //   results-fzt.txt; the freeze stage's ReadAllText was refused so on
    //   Windows 11 26300); what they do read is whole;
    // - every flip reaches the job, in order; once the readers stop, both
    //   files read the last state within the settle.
    //
    // The test's own writer, the operator, takes `gate`'s write side, the
    // readers its read side: a write of the operator's own refuses such a
    // reader, or is read half made, as any writer's on Windows, and is not
    // the jailer's to answer for. The jailer takes no part in the gate.
    fn readers_never_refused(version: Version) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, RwLock};
        const FLIPS: usize = 1000;
        const SHARING_WRITE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
        let dir = temp_dir(&format!("readers-{version:?}"));
        let control = dir.join(version.control());
        let (control_whole, events_whole): (&'static [&'static str], &'static [&'static str]) = match version {
            Version::V1 => (&["THAWED\n", "FROZEN\n", "THAWED", "FROZEN"], &[]),
            Version::V2 => (&["0\n", "1\n", "0", "1"], &["populated 1\nfrozen 0\n", "populated 1\nfrozen 1\n"]),
        };
        let gate = Arc::new(RwLock::new(()));
        let stop = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        for (i, share) in [SHARING_WRITE, FILE_SHARE_READ, SHARING_WRITE, FILE_SHARE_READ].into_iter().enumerate() {
            let (path, whole) =
                if version == Version::V2 && i >= 2 { (dir.join(fv::EVENTS), events_whole) } else { (control.clone(), control_whole) };
            let (gate, stop) = (gate.clone(), stop.clone());
            readers.push(std::thread::spawn(move || (path.clone(), hammer(path, share, whole, gate, stop))));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
        let job = Arc::new(Mutex::new(FakeJob::default()));
        let mut shared = SharedJob(job.clone());
        let mut freezer = Freezer::of(Files::create(&dir, version, State::Thawed).unwrap()).unwrap();
        freezer.before_resume(&mut shared).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let writer = {
            let (job, done, control, gate) = (job.clone(), done.clone(), control.clone(), gate.clone());
            std::thread::spawn(move || {
                let mut refused_by_the_jailer = 0;
                let mut lost = None;
                'flips: for i in 0..FLIPS {
                    let value = match (version, i % 2 == 0) {
                        (Version::V1, true) => "FROZEN",
                        (Version::V1, false) => "THAWED",
                        (Version::V2, true) => "1",
                        (Version::V2, false) => "0",
                    };
                    refused_by_the_jailer += write_over(&control, value, &gate);
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                    while job.lock().unwrap().0.len() <= i {
                        if std::time::Instant::now() > deadline {
                            lost = Some(i);
                            break 'flips;
                        }
                        std::thread::yield_now();
                    }
                }
                done.store(true, Ordering::Relaxed);
                (refused_by_the_jailer, lost)
            })
        };
        while !done.load(Ordering::Relaxed) {
            if let Some(ev) = freezer.watch.wait(Some(50)).unwrap() {
                freezer.woken(&mut shared, usize::from(ev == Event::Settled)).unwrap();
            }
        }
        let (refused_by_the_jailer, lost) = writer.join().unwrap();
        stop.store(true, Ordering::Relaxed);
        let seen: Vec<(PathBuf, Seen)> = readers.into_iter().map(|r| r.join().unwrap()).collect();
        // The readers gone, what is still to be written back is, by the settle.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(u64::from(fv::SETTLE_MS) * 3);
        while let Some(ev) = freezer.watch.wait(Some(fv::SETTLE_MS * 2)).unwrap() {
            freezer.woken(&mut shared, usize::from(ev == Event::Settled)).unwrap();
            if std::time::Instant::now() > deadline {
                break;
            }
        }
        let flips = job.lock().unwrap().0.clone();
        for (path, s) in &seen {
            eprintln!(
                "{version:?}: {} sharing {}: {} reads, {} refused {:?}, not whole {:?}",
                path.file_name().unwrap().to_string_lossy(),
                if s.share == SHARING_WRITE { "read|write" } else { "read alone" },
                s.reads,
                s.refused,
                s.first_refusals,
                s.torn
            );
        }
        eprintln!("{version:?}: {} flips; the operator's write refused by the jailer's write-back {refused_by_the_jailer} times", flips.len());
        for (path, s) in &seen {
            assert!(s.reads > 0, "{version:?}: {} never read", path.display());
            assert!(s.torn.is_empty(), "{version:?}: {} read not whole: {:?}", path.display(), s.torn);
            if s.share == SHARING_WRITE {
                assert_eq!(s.refused, 0, "{version:?}: {} refused a reader sharing writing: {:?}", path.display(), s.first_refusals);
            }
        }
        assert_eq!(lost, None, "{version:?}: a flip did not reach the job in 10 s");
        assert!(flips.len() == FLIPS && flips.iter().enumerate().all(|(i, f)| *f == (i % 2 == 0)), "{version:?}: flips {flips:?}");
        let last = if FLIPS % 2 == 1 { State::Frozen } else { State::Thawed };
        assert_eq!(content(&control).as_bytes(), version.canonical(last), "{version:?}: the control file not written back");
        if version == Version::V2 {
            assert_eq!(content(&dir.join(fv::EVENTS)).into_bytes(), fv::events(true, last == State::Frozen), "cgroup.events not written");
        }
        drop(freezer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // An operator's write that lands between the jailer's read of the
    // control file and its write-back is applied, never written over (the
    // write-back undid it before: `test_readers_are_never_refused_v2` lost
    // a flip so, agent-state/win2/results-fz-readers-before.txt). The
    // jailer's steps of a read are run by hand here, the write put between.
    #[test]
    fn test_a_write_after_the_read_is_applied() {
        let dir = temp_dir("raced");
        let mut freezer = Freezer::of(Files::create(&dir, Version::V2, State::Thawed).unwrap()).unwrap();
        let mut job = FakeJob::default();
        freezer.before_resume(&mut job).unwrap();
        write(&dir, "cgroup.freeze", "1");
        drain(&mut freezer, &mut job);
        assert_eq!((job.0.clone(), content(&dir.join("cgroup.freeze"))), (vec![true], "1\n".to_owned()));
        // The operator thaws, in a form to be written back; the jailer reads it.
        write(&dir, "cgroup.freeze", "0");
        let (request, canonical, seen) = freezer.files.read().unwrap().unwrap();
        assert_eq!((request, canonical), (fv::Request::Set(State::Thawed), false));
        freezer.control.state = State::Thawed;
        freezer.apply(&mut job, State::Thawed).unwrap();
        // The operator freezes again before the write-back.
        write(&dir, "cgroup.freeze", "1");
        let Freezer { files, watch, control, .. } = &mut freezer;
        control.write_back(files, watch, &seen).unwrap();
        assert_eq!(content(&dir.join("cgroup.freeze")), "1", "the write-back wrote over the operator's write");
        assert!(!control.restore_pending);
        // The change notification brings the write; it is applied.
        drain(&mut freezer, &mut job);
        assert_eq!(job.0, [true, false, true], "the operator's write was lost");
        assert_eq!(content(&dir.join("cgroup.freeze")), "1\n");
        assert_eq!(content(&dir.join("cgroup.events")), "populated 1\nfrozen 1\n");
        drop(freezer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_readers_are_never_refused_v1() {
        readers_never_refused(Version::V1);
    }

    #[test]
    fn test_readers_are_never_refused_v2() {
        readers_never_refused(Version::V2);
    }

    // A failed freeze is the jail's end, never a jail left running against
    // the request.
    #[test]
    fn test_a_failed_freeze_fails() {
        struct Refuses;
        impl JobFreeze for Refuses {
            fn set(&mut self, _: bool) -> Result<(), i32> {
                Err(0xC000_0022u32.cast_signed())
            }
        }
        let dir = temp_dir("refuses");
        set_version(Version::V1);
        let mut freezer = Freezer::for_exec(&dir).unwrap();
        write(&dir, "freezer.state", "FROZEN\n");
        let err = freezer.before_resume(&mut Refuses).unwrap_err();
        assert_eq!(err.to_string(), "freezing the job: NTSTATUS 0xC0000022");
        drop(freezer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    // The real call on this host: the self-check (a spinner frozen, its CPU
    // standing still, thawed) passes.
    #[test]
    fn test_self_check() {
        // The test binary is this crate's: its C runtime start spins with
        // the variable set, as the jailer's does.
        let t = std::time::Instant::now();
        self_check().unwrap();
        eprintln!("self-check: {} ms", t.elapsed().as_millis());
    }
}
