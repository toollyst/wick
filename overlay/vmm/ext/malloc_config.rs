// Copyright 2026 toollyst contributors.
// SPDX-License-Identifier: Apache-2.0

//! The configuration of macOS's allocator that Firecracker runs with.
//!
//! On Linux, Firecracker's release is built against musl, whose allocator
//! (mallocng) takes no configuration. macOS's libmalloc does, from the
//! environment only, once, when libSystem starts and before any of the
//! program's code runs (`_malloc_initialize`, libmalloc malloc.c). Its defaults
//! spread a process's small allocations over one magazine or allocation slot
//! per CPU (or CPU cluster) and keep freed memory for reuse; Firecracker's own
//! memory then goes over upstream's 5 MiB budget for the VMM's part
//! (docs/COMPATIBILITY.md, "VMM memory besides the guest"). [`MALLOC_ENV`] is
//! what keeps it under: one magazine or slot (`MallocMaxMagazines=1`) and
//! libmalloc's space-efficient mode, which gives freed memory back
//! (`MallocSpaceEfficient=1`).
//!
//! libmalloc-812 (macOS 27) runs its xzone allocator by default on Apple
//! silicon (malloc_config.c, `_malloc_should_enable_xzone`); there
//! `MallocMaxMagazines=1` also puts the process's pointer-holding allocations
//! in one bucket instead of four (xzone_malloc.c, `override_ptr_bucket_count`).
//! musl's allocator has no such buckets, and xzone with one still keeps
//! pure-data allocations apart from them: not weaker than Firecracker on Linux,
//! weaker than macOS's default (SECURITY.md, "Heap"). libmalloc-657 and
//! -792 (macOS 15 and 26) run the magazine allocator, which has no buckets.
//!
//! Since only the environment a program starts with counts, Firecracker
//! starts again with it: [`before_main`], run by the binary before `main`
//! (no thread, no descriptor of its own, nothing allocated that it keeps),
//! execs Firecracker's own executable with the same arguments and
//! [`MALLOC_ENV`] added when the environment lacks it. The jailer sets
//! [`MALLOC_ENV`] itself (overlay/jailer/platform/macos), so a jailed
//! Firecracker never execs again. A variable of [`MALLOC_ENV`] set to another
//! value is refused, loudly: Firecracker would otherwise run over its budget,
//! or silently drop the value given. A failed exec ends Firecracker, loudly:
//! it never runs without [`MALLOC_ENV`]. So does a file at its executable's
//! path that is no longer the one it started from (renamed over it since):
//! Firecracker never starts another file in its place.

use std::ffi::{CStr, CString};

/// libmalloc's variables Firecracker runs with, and their values. The jailer
/// has the same list (overlay/jailer/platform/macos, `MALLOC_ENV`).
pub const MALLOC_ENV: [(&str, &str); 2] =
    [("MallocMaxMagazines", "1"), ("MallocSpaceEfficient", "1")];

/// What [`before_main`] does with an environment.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// The environment has [`MALLOC_ENV`]: run.
    Run,
    /// Exec again with these variables (`name=value`) added.
    Exec(Vec<CString>),
    /// A variable of [`MALLOC_ENV`] has another value: refuse to start.
    Refuse {
        /// The variable.
        name: &'static str,
        /// The value it has.
        value: String,
        /// The value Firecracker needs.
        needed: &'static str,
    },
}

/// What to do with the environment `env` (`name=value` entries). As
/// libmalloc's `getenv`, the first entry of a name counts.
pub fn plan<'a>(env: impl IntoIterator<Item = &'a [u8]> + Clone) -> Plan {
    let mut missing = Vec::new();
    for (name, needed) in MALLOC_ENV {
        let value = env.clone().into_iter().find_map(|entry| {
            entry
                .strip_prefix(name.as_bytes())
                .and_then(|rest| rest.strip_prefix(b"="))
        });
        match value {
            Some(value) if value == needed.as_bytes() => {}
            Some(value) => {
                return Plan::Refuse {
                    name,
                    value: String::from_utf8_lossy(value).into_owned(),
                    needed,
                };
            }
            None => missing.push(CString::new(format!("{name}={needed}")).expect("no NUL")),
        }
    }
    if missing.is_empty() {
        Plan::Run
    } else {
        Plan::Exec(missing)
    }
}

/// The message [`before_main`] refuses with.
pub fn refusal(name: &str, value: &str, needed: &str) -> String {
    format!(
        "Error: Firecracker on macOS runs with {name}={needed} (libmalloc), but the \
         environment sets {name}={value}; unset it or set it to {needed} (see \
         SECURITY.md, \"Heap\")\n"
    )
}

/// Execs Firecracker again with [`MALLOC_ENV`] when its environment lacks it,
/// and refuses one that sets it otherwise; see the module. Run by the binary
/// before `main` (firecracker's main.rs places it in `__mod_init_func`):
/// returns only when the environment has [`MALLOC_ENV`], and otherwise
/// replaces the process or ends it with an error on standard error.
#[unsafe(no_mangle)]
pub extern "C" fn wick_malloc_config_before_main() {
    before_main();
}

/// See [`wick_malloc_config_before_main`].
pub fn before_main() {
    // SAFETY: crt's environment and arguments, which nothing changes before
    // main; each entry is a NUL-terminated string.
    let (environ, argv) = unsafe { (*libc::_NSGetEnviron(), *libc::_NSGetArgv()) };
    let entries = environment(environ);
    let added = match plan(entries.iter().map(|entry| entry.to_bytes())) {
        Plan::Run => return,
        Plan::Exec(added) => added,
        Plan::Refuse {
            name,
            value,
            needed,
        } => fail(&refusal(name, &value, needed), vmm_exit::BAD_CONFIGURATION),
    };

    let mut path = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is of the size given.
    let len = unsafe {
        libc::proc_pidpath(
            libc::getpid(),
            path.as_mut_ptr().cast(),
            libc::PROC_PIDPATHINFO_MAXSIZE as u32,
        )
    };
    let Ok(len @ 1..) = usize::try_from(len) else {
        let err = std::io::Error::last_os_error();
        fail(
            &format!(
                "Error: Firecracker could not find its executable to start with libmalloc's configuration: {err}\n"
            ),
            vmm_exit::GENERIC_ERROR,
        );
    };

    // The path names the file this process started from, or the exec would
    // run another: macOS has no exec of a descriptor (xnu's syscalls.master:
    // execve, __mac_execve and posix_spawn each take a path), so a file renamed
    // over the path since the start must be refused here.
    if let Err(why) = same_file_as_running(&path[..=len]) {
        fail(
            &format!(
                "Error: Firecracker could not start again with libmalloc's configuration: {why}\n"
            ),
            vmm_exit::GENERIC_ERROR,
        );
    }

    let mut envp: Vec<*const libc::c_char> = entries.iter().map(|entry| entry.as_ptr()).collect();
    envp.extend(added.iter().map(|entry| entry.as_ptr()));
    envp.push(std::ptr::null());
    // SAFETY: a NUL-terminated path (the buffer is zeroed past `len`), crt's
    // NULL-terminated argv, and a NULL-terminated array of strings that live
    // until the call.
    unsafe { libc::execve(path.as_ptr().cast(), argv.cast(), envp.as_ptr()) };
    let err = std::io::Error::last_os_error();
    let path = String::from_utf8_lossy(&path[..len]);
    fail(
        &format!(
            "Error: Firecracker could not start again with libmalloc's configuration (exec of {path}): {err}\n"
        ),
        vmm_exit::GENERIC_ERROR,
    );
}

/// `struct proc_regionwithpathinfo` (sys/proc_info.h), which `libc` lacks.
#[repr(C)]
struct RegionWithPathInfo {
    pri_protection: u32,
    pri_max_protection: u32,
    pri_inheritance: u32,
    pri_flags: u32,
    pri_offset: u64,
    pri_behavior: u32,
    pri_user_wired_count: u32,
    pri_user_tag: u32,
    pri_pages_resident: u32,
    pri_pages_shared_now_private: u32,
    pri_pages_swapped_out: u32,
    pri_pages_dirtied: u32,
    pri_ref_count: u32,
    pri_shadow_depth: u32,
    pri_share_mode: u32,
    pri_private_pages_resident: u32,
    pri_shared_pages_resident: u32,
    pri_obj_id: u32,
    pri_depth: u32,
    pri_address: u64,
    pri_size: u64,
    prp_vip: libc::vnode_info_path,
}

/// The SDK's sizeof(struct proc_regionwithpathinfo), which proc_pidinfo checks.
const REGION_WITH_PATH_INFO_SIZE: libc::c_int = 1272;
const _: () =
    assert!(std::mem::size_of::<RegionWithPathInfo>() == REGION_WITH_PATH_INFO_SIZE as usize);

/// `PROC_PIDREGIONPATHINFO` (sys/proc_info.h).
const PROC_PIDREGIONPATHINFO: libc::c_int = 8;

/// Whether the file at `path` (NUL-terminated) is the one this process runs
/// from: its device and inode against those of the file mapped at this
/// function's address, which the kernel reports whatever the file's name is
/// now (proc_pidinfo PROC_PIDREGIONPATHINFO, xnu bsd/kern/proc_info.c). Every
/// failure to find either is an error too.
fn same_file_as_running(path: &[u8]) -> Result<(), String> {
    let shown = String::from_utf8_lossy(&path[..path.len() - 1]).into_owned();
    let address = same_file_as_running as fn(&[u8]) -> Result<(), String> as usize as u64;
    // SAFETY: plain data; all zeroes is a valid value.
    let mut region: RegionWithPathInfo = unsafe { std::mem::zeroed() };
    let size = REGION_WITH_PATH_INFO_SIZE;
    // SAFETY: a buffer of the size given.
    let got = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            address,
            (&raw mut region).cast(),
            size,
        )
    };
    if got != size {
        return Err(format!(
            "it could not identify the file it runs from: {}",
            std::io::Error::last_os_error()
        ));
    }
    let start = region.pri_address;
    if !(start <= address && address - start < region.pri_size) {
        return Err(format!(
            "it could not identify the file it runs from: the region found ({start:#x}, {:#x} bytes) does not hold \
             its code ({address:#x})",
            region.pri_size
        ));
    }
    let running = &region.prp_vip.vip_vi.vi_stat;
    // SAFETY: plain data; all zeroes is a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a stat of our own.
    if unsafe { libc::stat(path.as_ptr().cast(), &mut st) } != 0 {
        return Err(format!(
            "it could not identify the executable at {shown}: {}",
            std::io::Error::last_os_error()
        ));
    }
    if (st.st_dev.cast_unsigned(), st.st_ino) != (running.vst_dev, running.vst_ino) {
        return Err(format!(
            "the executable at {shown} is no longer the one started (device {}, inode {} against {}, {}); \
             start it again",
            st.st_dev, st.st_ino, running.vst_dev, running.vst_ino
        ));
    }
    Ok(())
}

/// The entries of a NULL-terminated environment.
fn environment(mut environ: *const *mut libc::c_char) -> Vec<&'static CStr> {
    let mut entries = Vec::new();
    if environ.is_null() {
        return entries;
    }
    // SAFETY: a NULL-terminated array of NUL-terminated strings that live as
    // long as the process (crt's environment, unchanged before main).
    unsafe {
        while !(*environ).is_null() {
            entries.push(CStr::from_ptr(*environ));
            environ = environ.add(1);
        }
    }
    entries
}

/// Writes `message` to standard error and ends the process with `code`,
/// before anything else of Firecracker runs.
fn fail(message: &str, code: i32) -> ! {
    let mut rest = message.as_bytes();
    while !rest.is_empty() {
        // SAFETY: a write of a live buffer to standard error.
        let n = unsafe { libc::write(libc::STDERR_FILENO, rest.as_ptr().cast(), rest.len()) };
        let Ok(n @ 1..) = usize::try_from(n) else {
            break;
        };
        rest = &rest[n..];
    }
    // SAFETY: ends the process; nothing of Firecracker's is running yet.
    unsafe { libc::_exit(code) }
}

/// The variable that keeps a process of this crate's unit tests on
/// libmalloc's defaults ([`wick_malloc_config_test_before_main`]): only for a test that needs a
/// process as Firecracker never runs, with a deferred-reclamation ring (the
/// sandbox's refusal of one, `ext::sandbox`). Such a process is started with
/// [`MALLOC_ENV`]'s variables removed and this one set.
#[cfg(test)]
pub const TEST_DEFAULT_MALLOC: &str = "WICK_TEST_DEFAULT_MALLOC";

/// This crate's unit tests run libmalloc as Firecracker does: the test
/// binary starts again with [`MALLOC_ENV`] before `main`, by the same
/// [`before_main`], so that each sandbox profile is tested in the
/// allocator's configuration the product runs it in (the sandbox refuses a
/// process with a deferred-reclamation ring, which libmalloc's defaults make
/// from macOS 26). Not with [`TEST_DEFAULT_MALLOC`] set.
#[cfg(test)]
#[unsafe(no_mangle)]
pub extern "C" fn wick_malloc_config_test_before_main() {
    if std::env::var_os(TEST_DEFAULT_MALLOC).is_none() {
        before_main();
    }
}

#[cfg(test)]
core::arch::global_asm!(
    ".section __DATA,__mod_init_func,mod_init_funcs",
    ".p2align 3",
    ".quad _wick_malloc_config_test_before_main",
    ".text",
);

/// Firecracker's exit codes (`crate::FcExitCode`) this module ends with.
mod vmm_exit {
    pub const GENERIC_ERROR: i32 = crate::FcExitCode::GenericError as i32;
    pub const BAD_CONFIGURATION: i32 = crate::FcExitCode::BadConfiguration as i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(env: &[&'static str]) -> Vec<&'static [u8]> {
        env.iter().map(|entry| entry.as_bytes()).collect()
    }

    #[test]
    fn test_an_environment_without_the_variables_execs_with_both() {
        let env = entries(&["HOME=/x", "MallocStackLogging=1"]);
        assert_eq!(
            plan(env.iter().copied()),
            Plan::Exec(vec![
                CString::new("MallocMaxMagazines=1").unwrap(),
                CString::new("MallocSpaceEfficient=1").unwrap(),
            ])
        );
    }

    #[test]
    fn test_an_environment_with_one_execs_with_the_other() {
        let env = entries(&["MallocSpaceEfficient=1"]);
        assert_eq!(
            plan(env.iter().copied()),
            Plan::Exec(vec![CString::new("MallocMaxMagazines=1").unwrap()])
        );
        let env = entries(&["MallocMaxMagazines=1"]);
        assert_eq!(
            plan(env.iter().copied()),
            Plan::Exec(vec![CString::new("MallocSpaceEfficient=1").unwrap()])
        );
    }

    #[test]
    fn test_an_environment_with_both_runs() {
        let env = entries(&["A=1", "MallocMaxMagazines=1", "MallocSpaceEfficient=1"]);
        assert_eq!(plan(env.iter().copied()), Plan::Run);
    }

    #[test]
    fn test_another_value_is_refused() {
        for (env, name, value) in [
            (&["MallocMaxMagazines=0"][..], "MallocMaxMagazines", "0"),
            (
                &["MallocMaxMagazines=4", "MallocSpaceEfficient=1"][..],
                "MallocMaxMagazines",
                "4",
            ),
            (
                &["MallocMaxMagazines=1", "MallocSpaceEfficient=0"][..],
                "MallocSpaceEfficient",
                "0",
            ),
            (&["MallocSpaceEfficient="][..], "MallocSpaceEfficient", ""),
            (&["MallocMaxMagazines=01"][..], "MallocMaxMagazines", "01"),
        ] {
            assert_eq!(
                plan(entries(env).iter().copied()),
                Plan::Refuse {
                    name,
                    value: value.to_string(),
                    needed: "1"
                },
                "{env:?}"
            );
        }
    }

    #[test]
    fn test_the_first_entry_of_a_name_counts() {
        // As getenv, which libmalloc reads them with.
        let env = entries(&[
            "MallocMaxMagazines=1",
            "MallocMaxMagazines=4",
            "MallocSpaceEfficient=1",
        ]);
        assert_eq!(plan(env.iter().copied()), Plan::Run);
        let env = entries(&[
            "MallocMaxMagazines=4",
            "MallocMaxMagazines=1",
            "MallocSpaceEfficient=1",
        ]);
        assert!(matches!(plan(env.iter().copied()), Plan::Refuse { .. }));
    }

    #[test]
    fn test_a_longer_name_is_another_variable() {
        let env = entries(&["MallocMaxMagazinesX=4", "MallocSpaceEfficientY=0"]);
        assert_eq!(
            plan(env.iter().copied()),
            Plan::Exec(vec![
                CString::new("MallocMaxMagazines=1").unwrap(),
                CString::new("MallocSpaceEfficient=1").unwrap(),
            ])
        );
    }

    #[test]
    fn test_the_refusal_names_the_variable_and_the_value_needed() {
        let message = refusal("MallocMaxMagazines", "4", "1");
        assert!(message.contains("MallocMaxMagazines=1"), "{message}");
        assert!(message.contains("MallocMaxMagazines=4"), "{message}");
    }
}
