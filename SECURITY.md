# Security

wick's promise is Firecracker's isolation on every host, not a weaker "developer" version of it. This page says how
each of Firecracker's controls is held on Linux, macOS and Windows today, and what is not done yet. If you find a way
across one of the boundaries below, please report it privately.

## Reporting a vulnerability

Please report vulnerabilities in wick privately through GitHub:
[Report a vulnerability](https://github.com/toollyst/wick/security/advisories/new). Do not open a public issue.
Include the output of `firecracker --version`, the host (OS version, CPU), and the smallest reproduction you have.

wick's own code is everything outside `lib/firecracker`: the compatibility crates, the overlay modules, the patches
and the tools. A vulnerability that also affects upstream Firecracker on Linux (code in `lib/firecracker` that wick
does not change) belongs to the Firecracker project; report it to AWS as described in
[Firecracker's security policy](https://github.com/firecracker-microvm/firecracker/blob/main/SECURITY.md). If you are
not sure which, report it here and we will coordinate.

## Supported versions

Security fixes go into the latest release: `v<upstream>`, or a fix release `v<upstream>+wick.<N>` on it, and `main`.

## Verifying a release

Releases are built on GitHub-hosted runners by the release workflow
([`.github/workflows/release.yml`](.github/workflows/release.yml)) from a tag on `main`, after the dependency checks
([CONTRIBUTING.md](CONTRIBUTING.md#dependencies)) pass. Next to each archive, a release has:

- `SHA256SUMS`: the SHA-256 of every file in the release.
- `<binary>-<tag>-<os>-<arch>.cdx.json`, one for each binary in the archive: its SBOM (CycloneDX 1.5), every crate it
  is built from, with the version and the checksum or git commit `Cargo.lock` pins.
- Attestations, signed through Sigstore by the workflow run that built the release and recorded for this repository:
  SLSA build provenance for the archive and for each binary in it, and each binary's SBOM for the archive and for
  that binary.

Check the files against `SHA256SUMS` (on Linux, `sha256sum -c SHA256SUMS`):

```sh
shasum -a 256 -c SHA256SUMS
```

Then check that this repository's release workflow built the archive, from the tag you expect, with the
[GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify wick-v1.18.0-darwin-aarch64.tgz --repo toollyst/wick \
    --signer-workflow toollyst/wick/.github/workflows/release.yml \
    --source-ref refs/tags/v1.18.0 --deny-self-hosted-runners
```

The same command works on each extracted binary (`release-v1.18.0-darwin-aarch64/firecracker-v1.18.0-darwin-aarch64`,
`jailer-v1.18.0-darwin-aarch64`, ...).
`--predicate-type https://cyclonedx.org/bom` checks the SBOM attestation instead of the provenance, and
`--format json` prints what was verified, including the commit the release was built from.

The macOS binaries carry only an ad-hoc code signature (it is not signed with an Apple Developer ID); the attestation
is what ties it to this repository.

## Threat model

The same as upstream Firecracker's
([design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md#threat-containment)):

- **Assumed hostile:** everything inside the guest, including a guest kernel that has been taken over, and anything
  the guest can send to the host through a device.
- **Trusted:** the host, the user who starts Firecracker, the wick binaries, and the files the operator passes in
  (kernel, drives, snapshots).

## How each control is held

| Control | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Hardware virtualization, one kernel per VM | KVM | Hypervisor.framework | Windows Hypervisor Platform |
| Minimal device model | upstream | upstream's device code; host-side backends are wick's | upstream's device code; host-side backends are wick's |
| System call filter | per-thread seccomp-BPF (upstream) | **in place:** a Seatbelt profile, process-wide, in upstream's two phases: until the microVM is built (when Linux installs the VMM thread's filter) it allows what building takes; then it narrows for good, as no extension can be issued, taken or released any more, to 102 system calls, 15 Mach traps and 7 kernel MIG routines (and `mach_exception_raise`, the kernel's own message for a thread's fault, below), each tied to the Linux rule it stands for, or to what libsystem calls on a path the rule's call takes (`__pthread_canceled`, which a cancellation point such as `read` or `nanosleep` makes when a handled signal, the vCPU kick's included, interrupts it with EINTR: it reads or sets the calling thread's own cancellation state only, XNU bsd/kern/kern_sig.c, and no thread can be marked cancelled, as `__pthread_markcancel` is in no list; `test_a_handled_signal_interrupts_a_blocking_call`) (on macOS 27, where PV steal time is offered, also a thread's own CPU time and `thread_info`: below) (any other one is a denial, below). Always: no program execution, no fork, no IP networking, no Mach service lookups (but the one starting a vmnet interface makes while the microVM is built: `test_vmnet_lookup_is_setups_only`), no IOKit, no sysctl writes, no file mapped executable, no `MAP_JIT`; after narrowing also no listening socket made, no sysctl reads, no signal action set (upstream's filters allow `rt_sigaction` then for SIGABRT only, which Seatbelt cannot tell apart, so this is stricter; a panic's `abort()` still ends by SIGABRT: `test_a_run_phase_sigaction_is_a_denial`, `test_the_other_ends_are_unchanged_without_a_denied_call`), `fcntl` commands only from its list, no change to a file's mode, owner, flags, times or extended attributes, driver ioctls only for the terminal's settings and a block device's sizes, and no anonymous mapping asking for `PROT_EXEC` (checked in the compatibility libc: macOS has no kernel rule for it, so a raw system call is not checked; `test_executable_mappings_are_denials`). A denied operation of any kind ends Firecracker inside the call, except a file outside what is allowed, which fails with an error as outside a chroot: every denying rule's action is `(with send-signal SIGKILL)`, which the kernel delivers before the call returns, so the call never returns to its thread and no signal mask, disposition or thread state can keep Firecracker running (`test_a_denied_call_never_returns_to_its_thread`, `test_an_ignored_or_replaced_sigsys_cannot_keep_a_denied_process_running`, `test_a_process_wide_sigsys_block_cannot_keep_a_denied_process_running`; macOS 27.2 here, and Seatbelt's action alone on macOS 15 and 26 in CI run 43497862443, `tools/macos/seatbelt-kill-probe.py`), as Linux skips the call and forces SIGSYS on that thread, whose handler then exits (kernel/seccomp.c `__seccomp_filter`, `SECCOMP_RET_TRAP`, the `default_action` of each of upstream's filters, resources/seccomp/{aarch64,x86_64}-unknown-linux-musl.json; the handler's `_exit`, vmm/src/signal_handler.rs). A number the kernel has no call for is checked as `SYS_invalid`, which no list has (XNU bsd/dev/arm/systemcalls.c `unix_syscall`), so it is a denial too (`test_an_unknown_syscall_number_is_a_denial`). The end itself differs: SIGKILL, with the sandbox's exit reason (namespace 25, `OS_REASON_SANDBOX`) and a crash report, where Linux exits 148 with upstream's log line and fault metric. Seatbelt has no action that traps the calling thread; a catchable signal goes to the process, and with SIGSYS, wick's end until 81072df, the denied call returned `EPERM` to a thread that ran on, denied whatever else it asked, for a median 0.74 to 1.9 ms and at most 14.8 ms before the exit (macOS 27.2 at b05cd23, load average 13 to 18), and code already running in Firecracker could keep it alive (SIGSYS ignored, or blocked). Firecracker's parent can tell this end from any other SIGKILL by its exit reason (docs/COMPATIBILITY.md, the denied-call row); the API process's denials end Firecracker as upstream's do, since Firecracker is that process's parent (below). Seatbelt skips the rule on the number of some system calls (`write`, `open`, `socket`, `ioctl`, ...) when a rule allows the operation they make, 92, 102 and 104 of them on macOS 15, 26 and 27; where an older major checks the number of one that 27 lets through, the run phase lists it, so every major behaves alike; each is tied to the rule that decides it, and 8 that nothing decides (`getpid`, `umask`, ...) are written down (docs/PORTING.md row 1; `test_unfiltered_syscalls_are_limited_by_their_rule`, `ext::sandbox` unit tests, `test_narrowing_is_one_way`, every `boot-test` stage, `tools/macos/sandbox-discovery.sh`) | **in place:** a process mitigation profile, each mitigation tied to the seccomp rule it stands for, in upstream's two phases: until the microVM is built (where Linux installs the VMM thread's filter) it sets what building takes — no child processes, no win32k, strict handle checks, extension points disabled, Microsoft-signed images only; then it narrows for good, adding no dynamic code and the image-load restrictions (no remote or low-label images, System32 first). A denied operation ends Firecracker with upstream's bad-syscall code where Windows reports it (an executable mapping, a handle the process does not hold), else fails closed (`ext::sandbox` unit tests: `test_win32k_policy`, `test_dynamic_code_policy`, `test_narrow_ends_the_setup_phase`, `test_denied_operation_exits_as_seccomp`, `test_denied_operations_fail_closed`; the run is found with `tools/windows/mitigation-audit.ps1`). Not at parity: no counterpart of seccomp's list of allowed `ioctl` requests; a jailed Firecracker reaches the I/O-control code of every driver its token opens, 87 on Windows Server 2022 (`fs-probe devjail`; [docs/windows-jail-reach.md](docs/windows-jail-reach.md)) |
| Jailer: chroot | upstream | **in place:** upstream's jailer; `chroot(2)`, entered by Firecracker right after the exec, and a Seatbelt file rule limited to the jail (`jailer-test jail`) | **in place:** upstream's jailer; the jail as a drive letter of its own with the current directory its root, and a protected directory ACL open to the jail's SID (`jailer-test.ps1 isolation`, `drives`) |
| Jailer: network namespace | upstream | Seatbelt denies IP networking to every Firecracker; `--netns <dir>` names the jail's network, a directory of endpoints the operator made, where Firecracker makes its network endpoints (each jail's are in a directory of its own there, `<dir>/<id>/`, which only that jail and the directory's owner or root reach, as a TAP is its owner's: `test_each_jail_has_a_network_directory_of_its_own`, `test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint`; an endpoint sends frames only to the switch's sockets, directly in `<dir>`: `test_a_jails_endpoint_takes_only_the_switch_as_a_peer`; two jails of one uid are kept apart by the profile alone, see below), and the sandbox lets a jail with a network reach Unix sockets only in its own directory there, directly in `<dir>` and in the jail (`test_jail_network_profile_limits_sockets`, `test_endpoint_in_network_directory`, `jailer-test netns`) | **in place:** `--netns <dir>` names the jail's network, a directory of endpoints the operator made, where Firecracker makes its network endpoints (in the jail's own directory in it, `<dir>\<id>`, which only that jail and the operator reach: no other jail can connect to its endpoints, delete them or take their names, as a TAP is its owner's on Linux, and a second jail of a running id is refused as busy; `test_the_network_directory_grants_no_jail`, `test_each_jail_has_a_network_directory_of_its_own`, `test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint`: written, compiled and unit-tested on CI; `jailer-test.ps1 netns`, the elevated stage, and `jailer-test.ps1 netguest` passed with this layout in CI run 43442912128, 861d365, elevated), and the jail's copy of Firecracker gets no IP networking at all: Windows Filtering Platform block filters on its application id at every connect, bind, listen and accept layer, IPv4 and IPv6, in a session that ends with the jailer. Needs an elevated jailer (adding a filter is an administrator's right, as `setns` needs root); refused loudly without one. An AppContainer was not usable: WHP refuses to run inside one (`jailer-test.ps1 netns`, `refuse`) |
| Jailer: uid/gid | upstream | **in place:** dropped right after the chroot, checked that root cannot be regained (`jailer-test jail`, `test_enter_needs_root`) | **in place:** a restricted token below medium integrity, without the user's SID and with a random SID per jail: no access to the user's files, another jail, or other processes, and, since the jail's integrity level is above low, no access from a plain low-integrity process of the same user either (`jailer-test.ps1 isolation`, `low`); no privilege but traversal (`test_tokens_keep_only_traversal`): below medium integrity no privilege can be enabled, "Lock pages in memory" included, so a jailed Firecracker cannot map large pages itself; the jailer makes them for it, as sections no larger in all than `hugetlb.2MB.max` (`jailer-test.ps1 hugepages`, docs/PORTING.md row 10) |
| Jailer: PID namespace | upstream | in place in every jail: the sandbox keeps every other process out of Firecracker's reach (no process information, no signal); `--new-pid-ns` gives upstream's process tree and drops the signals a namespace's init does not get from outside; the pid is the host's (`test_no_other_process_in_reach`, `jailer-test pidns`) | **in place** in every jail: no process or thread outside the jail opens to Firecracker, a process snapshot shows it none, and it is not on the jailer's console (no console control events or typed input; the jailer relays the console); `--new-pid-ns` returns as upstream's jailer does. Whether a pid is in use still shows (`jailer-test.ps1 pidns`) |
| Jailer: cgroups (memory, CPU) | upstream | memory **in place** (jetsam limit, killed at the limit as by the OOM killer); CPU **in place** (`cpu.max` / `cpu.cfs_quota_us` → a kernel CPU limit on the whole VMM, throttled once it used its share of each second); `cpuset` naming every CPU and memory node accepted (no restriction), as is a limit macOS does not have set to no limit (`pids.max=max`, `memory.high=max`, ...); the freezer through upstream's files next to the jail, kept by a root supervisor per jail (below); other controllers, and those limits with a number, refused, each with its reason (`jailer-test limits`, `jailer-test memory`, `jailer-test cpu`, `jailer-test freeze`, `test_cpu_limit_holds`, `test_other_controllers_are_refused`, `test_no_limit_values_are_accepted`, `test_only_no_limit_is_accepted_of_a_limit_macos_lacks`) | CPU **in place** through a Job Object (CPU rate hard cap from Firecracker's start or a CPU weight); memory **in place, with a window**: the Job Object's memory limit holds private memory, and the jailer counts sections every 1 ms and ends the jail with 137 past the limit (see below; `jailer-test.ps1 sections`, passed in CI run 43545368906, 305a806, and each saved run since, and on the PC at 305a806 and df0bf87); `cpuset.cpus` as the job's affinity; the freezer through upstream's files next to the jail, kept by the jailer, which freezes the job (below); other controllers refused with the reason (`jailer-test.ps1 limits`, `jailer-test.ps1 cpu`, `jailer-test.ps1 cpuset`, `jailer-test.ps1 weight`, `jailer-test.ps1 refuse`, `jailer-test.ps1 freeze`) |
| Heap allocator | musl's mallocng (upstream's release is built for `*-unknown-linux-musl`): no type isolation | libmalloc with `MallocMaxMagazines=1` and `MallocSpaceEfficient=1`, the jailer's environment or Firecracker's own start again before `main`; on macOS 27 (xzone) one pointer bucket instead of four, so not weaker than Linux, whose mallocng keys its groups by size class alone (musl src/malloc/mallocng/malloc.c, `malloc`: `ctx.active[sc]`), and weaker than macOS's default (below, Heap) | the process heap, unchanged |

The sandbox is installed where upstream installs its seccomp filters and keeps upstream's flags: on by default, off
with `--no-seccomp`. On macOS a process may lift its own CPU limit and the allow-list is what denies that, so a
jailed Firecracker with a CPU limit refuses `--no-seccomp`. `--seccomp-filter FILE` is refused outside Linux, because a BPF filter cannot be enforced there;
wick never accepts a security flag it cannot honor. If the host sandbox cannot be installed, Firecracker fails to
start rather than running without it.

On macOS 27, where PV steal time is offered, the narrowed profile also allows `thread_selfusage`, a thread's own
CPU time (XNU bsd/kern/kern_resource.c, `thread_get_runtime_self`; Linux's VMM filter has `clock_gettime`), and the
kernel MIG routine `thread_info`, with which a thread of the microVM reads a vCPU thread's run state and CPU time
(docs/COMPATIBILITY.md, PV time). KVM reads a vCPU thread's run delay in the kernel, so `thread_info` stands for no
rule of upstream's filter. A compromised VMM gains nothing from it it could not already see: the routine takes a
thread inspect port and only reads (osfmk/mach/thread_act.defs `thread_info`; osfmk/kern/thread.c
`thread_info_internal`: basic, identifier, scheduling and extended information, a debug flavor only on DEVELOPMENT
kernels), and the only thread ports the VMM can name are its own threads', as no rule reaches another task's
(`task_for_pid`, `task_threads` and the task name traps stay denied). The routines that change a thread
(`thread_set_state`, `thread_policy_set`, `thread_suspend`) are denied once the microVM is built
(`thread_policy_set` is allowed before, for the vCPU threads' latency tier; `test_thread_reads_are_pv_times_only`).
On macOS 15 and 26 neither is in the profile.

Every profile, the API process's too, allows the kernel MIG routine `mach_exception_raise`, where Seatbelt knows the
name (`defined?`; macOS 15's and 27's do). Firecracker never calls it: it is the message by which the kernel turns a
thread's fault or trap into SIGSEGV, SIGBUS or SIGTRAP. The kernel sends it itself, on the faulting thread, to the
host's exception port, a kernel object (XNU osfmk/kern/exception.c `exception_triage_thread` and `exception_deliver`,
with the behaviour bsd/uxkern/ux_handler.c `ux_handler_setup` gives the port, EXCEPTION_DEFAULT |
MACH_EXCEPTION_CODES), and a message to a kernel object is served on the sending thread after a check against its
task's MIG filter (osfmk/kern/ipc_kobject.c `ipc_kobject_server_internal`, `task_get_mach_kobj_filter_mask`). macOS
15 applies the filter to it ("deny(1) syscall-mig 53", CI run 43396747298 on 15.8.2, with hundreds of repeats for
one process: the message fails, the thread returns to the faulting instruction and faults again); macOS 26 and 27 do
not consult it for this message (measured on 27.2: the two tests below pass with the rule removed). So from da01de1
(2026-11-11, the profile's first `syscall-mig` rules; no release holds it) until the routine was listed, a fault of
the sandboxed Firecracker or API process on macOS 15 raised the denial's SIGSYS and never its own signal: Firecracker
ended with exit 148 and "the host sandbox denied a system call" in place of upstream's end for the fault, and a fault
the userfaultfd backend serves by its signal would have ended the microVM the same way. That failed closed (the
process ended), but as the wrong event. Linux raises a fault's signal in the kernel, with no call a filter sees.

What the allowance lets a compromised VMM do itself, from the source: nothing it cannot already do. The kernel picks
a kernel object's routine by the message's id alone (ipc_kobject.c `mig_init`, `find_mig_hash_entry`), so the allowed
id passes the filter whichever kernel object the process sends it to, but it always runs `catch_mach_exception_raise`
(ux_handler.c), which fails unless the destination is the host's exception port. The process holds no send right to
that port and nothing allowed gives it one: the host's exception ports are read with the host's privileged port
(`host_get_exception_ports`; the privileged port itself is denied, `mach-priv-host-port`), a task's or thread's with
`task_get_exception_ports` or `thread_get_exception_ports`, and none of these, nor a swap routine, is in a list; Mach
lookups are denied. Holding one, it could only raise the signal the exception's type and code name (ux_exception.c
`ux_exception`) on the thread whose port the message carries (`handle_ux_exception`), and the only thread ports the
process can name are its own threads', which it can already signal (`__pthread_kill`); the routine reads nothing and
reaches no other process. The API process sends no Mach message at all (`mach_msg2_trap` is not in its list).
Measured on macOS 27.2: the process's own `mach_exception_raise` message to its task port, carrying its thread and
task ports, is answered KERN_FAILURE and raises nothing, with or without a profile, and `task_get_exception_ports`
is a denial in every profile (`test_an_exception_message_of_its_own_does_nothing`); a fault ends by its own signal
in each profile (`test_a_fault_is_its_signal_under_each_profile`). On macOS 15.8.2 both tests, and the fault and
trap cases of `test_the_other_ends_are_unchanged_without_a_denied_call`, pass with the allowance (CI run 43403250054,
job `macos-seatbelt (macos-15)`, at 2ef0ff6), where those cases had ended 148 without it (run 43396747298).

### Heap

Firecracker's release on Linux is built against musl (`*-unknown-linux-musl`), whose allocator, mallocng, has no
type isolation: allocations of one size class share the same groups, whatever they hold. On macOS Firecracker runs
libmalloc with `MallocMaxMagazines=1` and `MallocSpaceEfficient=1` (`vmm::ext::malloc_config`), which upstream's
5 MiB budget for the VMM's own memory needs (docs/COMPATIBILITY.md, VMM memory besides the guest). libmalloc reads
both from the environment once, as libSystem starts and before any of the program's code (`_malloc_initialize`,
libmalloc-812 malloc.c), and no entitlement or API lets a program choose them otherwise. So the jailer puts them in
the environment it execs Firecracker with, and Firecracker launched without them starts again with them: an
initializer of the binary, before `main`, with no thread and no descriptor of its own, execs its own executable
(`proc_pidpath`) with crt's arguments as they are, the environment it has then (the one given, and what libraries'
initializers add before `main` in any run: CoreFoundation's `__CF_USER_TEXT_ENCODING`) with the two variables after
it, and every descriptor it was given (it has opened none, and an exec keeps what a launcher passed on): the binary's
`test_starting_again_keeps_arguments_environment_and_descriptors` compares each with a run that does not start
again. A variable set to another value is refused, naming the value needed (exit 152, upstream's bad-configuration
code), and a failed exec ends Firecracker with exit 1 and `Error: Firecracker could not start again with libmalloc's
configuration (exec of PATH): ERROR` on standard error, before any of its own code
(`test_a_failed_start_again_ends_firecracker_naming_why`: an environment that leaves the second exec over
`kern.argmax`, E2BIG): it never runs without them.

The file the second exec runs is the one at the running image's path (`proc_pidpath`), and macOS has no exec of a
descriptor (xnu's bsd/kern/syscalls.master: `execve`, `__mac_execve` and `posix_spawn` each take a path). So before
the exec Firecracker compares the device and inode of the file at that path with those of the file its code is mapped
from, which the kernel reports whatever that file's name is now (`proc_pidinfo` `PROC_PIDREGIONPATHINFO`, xnu
bsd/kern/proc_info.c). A file renamed over the path since the start (an upgrade in place, a rebuild) ends Firecracker
with exit 1 and `... the executable at PATH is no longer the one started (...); start it again`, and an unlinked one
with `could not find its executable` (`proc_pidpath` finds no path); failing to read either side ends it too, and the
other file never runs (`test_a_start_whose_executable_is_unlinked_or_replaced_meanwhile`: a start held before its
first instruction, `POSIX_SPAWN_START_SUSPENDED`, while the file is replaced or unlinked; with the comparison removed
the other file runs and the test fails). What is left is the few instructions between the comparison and `execve`: a
rename over the path inside them runs the new file. Making it needs write access to the executable's directory, which
already lets one replace the binary before any start; a jailed Firecracker, which runs a root-owned copy with the
variables set by the jailer, never starts again.

What it gives up, on libmalloc-812 (macOS 27), which runs its xzone allocator by default on Apple silicon
(malloc_config.c, `_malloc_should_enable_xzone`): `MallocMaxMagazines=1` also makes the pointer buckets one instead
of four (xzone_malloc.c, `override_ptr_bucket_count`). xzone picks the bucket of an allocation that carries no type
by a hash of its call site (malloc_type_internal.h, `malloc_callsite_fallback_type_descriptor`), and Rust's carry
none: the release binary calls `malloc` from 1102 places in 442 functions (Rust's allocator inlined, or
`__rust_alloc`, which tail-calls it, and the C code linked in; `objdump -d` of the binary at this commit). With four
buckets the objects of those call sites and libSystem's own allocations are spread over four sets of chunks that
never share memory; with one they share one. A use-after-free in the VMM can then reach an object from any call
site of its size class, as on Linux it can. This is weaker than
macOS's default for a process and not weaker than Firecracker on Linux, whose musl mallocng takes no caller or type
and keys its groups by the size class alone (src/malloc/mallocng/malloc.c, `malloc`: `sc = size_to_class(n)`,
`g = ctx.active[sc]`). The rest of xzone is kept; what
`MallocSpaceEfficient=1` changes is how much freed memory it keeps (no deferred reclaim, no huge cache, segments
given back: libmalloc's own report of its configuration, `MallocReportConfig`). libmalloc-657 and -792 (macOS 15
and 26) run the magazine allocator, which has no buckets; there the two variables only make one magazine and give
freed memory back (`Max Magazines: 1`, `Aggressive Madvise: 1` in the same report).

The configuration is checked on each launch: libmalloc's report on a direct launch, without the variables (two
reports, the second with them) and with them (one) (`test_a_direct_launch_starts_again_with_libmallocs_configuration`,
`test_a_launch_with_the_configuration_runs_without_starting_again`), another value refused before any of
Firecracker's code runs (`test_another_value_is_refused`, `ext::malloc_config` unit tests), the jailer's environment
(`test_firecracker_gets_libmallocs_configuration_from_the_jailer`) and the jailed Firecracker's own (`jailer-test
jail`).

On Windows Firecracker's heap is the process heap (`HeapAlloc`, Rust's `System`), with no type isolation either,
through wick's allocator (`libc::wick_alloc`), which changes only what a refusal does: by the size asked, null above
the host's commit limit, 137 above what the job's limit holds, else a reclaim, then the end with 137 (Fixed defects
below; `test_the_heaps_allocator_is_wicks`, and Firecracker's debug line at a VM's build, which `boot-test.ps1 boot`
checks).

Every planned mechanism above has been measured on its host with a probe
([`tools/windows/winprobe.c`](tools/windows/winprobe.c) on Windows); the [roadmap](docs/ROADMAP.md), milestone M5,
has the per-control details and results.

## Fixed defects

- **Windows, on a host with AMX: a stack overflow, or a stack that could not grow at the memory limit, on a thread
  with no stack guarantee ended the process with an access violation (0xC0000005) and no line of wick's** (every
  Windows release so far; found by the first CI windows job that ran on an Intel Xeon Platinum 8573C with AMX
  enabled, docs/COMPATIBILITY.md's `memory.max` row; fixed in the commit that adds this entry). The system dispatches a stack overflow on the thread's own
  stack, and what it puts there first is the exception's context with the thread's whole XSAVE area: 8256 bytes more
  with AMX's tile configuration and data than with AVX-512 (STACKASK: the dispatcher's frames 13.8 KiB against
  5.6 KiB on an Ice Lake Xeon). A thread made by `CreateThread` or a thread pool has no stack
  guarantee, and was left 4.9 KiB under the exception handler where it had 7.6 to 9.1 KiB; the handler or the stack
  filter then overflowed again, and the process ended with the access violation instead of 137 (the memory limit)
  or 0xC00000FD (the reserve's end) after wick's line. Five tests failed so
  (`test_a_stack_that_must_grow_at_the_limit_ends_with_137`, `test_a_stack_overflow_at_the_reserves_end_is_still_one`,
  `test_a_job_nested_in_one_that_dies_on_unhandled_exceptions_ends_by_its_own_limits`,
  `test_a_lazy_touch_at_the_reserves_end_is_a_loud_overflow`, `test_the_reclaimers_own_stack_page_is_not_waited_for`).
  The process ended either way, so nothing ran on that was meant to stop, and the jailer's accounting does not read
  the exit code (its count of sections ends the jail with 137 by itself); what was wrong is what the operator was
  told: an end at the memory limit read as a crash, with no line naming the thread. Now every thread is given a
  stack guarantee when it starts (a TLS callback, `windows_mm::at_thread_start`, for the main thread, Rust's,
  `CreateThread`'s, the pool's and the system's alike): the exception's context as this host sizes it
  (`InitializeContext2` for every XSAVE feature the system enables), the dispatcher's own 4 KiB, and 16 KiB for the
  handler (`windows_mm::HANDLER_STACK_BUDGET`). The guard region below the stack, which the system runs an overflow on
  when the stack cannot grow, is made by `SetThreadStackGuarantee` itself: 12288 bytes of guard pages below
  StackLimit before the call on a Rust and a pool thread, none on a `CreateThread` thread, and 28672 right after it
  on all three for a guarantee of 24576 (the guarantee and a page, `windows_mm::guard_region_for`); the same at their
  own start and after they grew 64 KiB, and 28672 on the process's main thread, given the guarantee at the
  process's attach (CI's STACKGUARANTEE and GUARDSEEN lines, Windows Server 2025; Learn's page for the call names no
  mechanism). This entry said twice what was not measured: edea8e38 touched the guard page to make the region, and
  12c8e7d8 committed it explicitly, saying the system makes it only at the stack's next growth; neither was
  needed, and the explicit commit is gone. A thread the system cannot give the guarantee is said by its ID at its
  start, which does not fail; at the job's memory limit the call is refused (`ERROR_COMMITMENT_LIMIT`, 1455) and
  leaves the guarantee and the guard pages as they were, never a guarantee without its region
  (`test_a_stack_guarantee_raised_at_the_limit_is_given_or_refused`, GUARANTEELIMIT: a raise of 64 KiB with every
  page of the job taken).
  The stack filter writes its line and the frames
  of a VMM that ends only with room for them, so it cannot fault before its exit with 137. The tests hold the room on every runner and kind of
  thread (STACKASK: at least the budget left under the handler; STACKUSE: at most the budget used), also with a
  larger XSAVE area simulated on a runner without AMX (8256 bytes, as AMX adds, and 16384:
  `WICK_TEST_XSAVE_EXTRA`); a runner with AMX remains the measured record, and GitHub assigns the windows job's
  runner at random (`test_every_thread_has_the_stack_guarantee`: the guard pages walked down from each kind of
  thread's StackLimit right after the call, at its start and after it grew 64 KiB, at least the context, the
  dispatcher's and the handler's bytes; `test_a_stack_guarantee_that_cannot_be_set_is_said`).
  What it costs: each thread has the guarantee and one page more below its stack from its start, untouched, as guard
  pages: by the sizes, 28 KiB a thread on a host without AMX and 40 KiB with it (Rust's threads had Rust's own
  guarantee of 20 KiB before, set by Rust's runtime after the loader's callback), charged to the job's commit, and so
  to `memory.max`, when the guarantee is set (`test_a_stack_guarantee_is_charged_when_it_is_set`, GUARDCHARGE: a
  thread's guarantee raised from 24576 to 90112 bytes grew its guard pages by 65536 and the process's commit by
  65536). A Firecracker has 5 threads and one a vCPU
  (the event loop, the API thread, the PIT's timer, the TSC-deadline timer, the irqfd watcher), 2 in its API process,
  and one each, when they run, for the userfaultfd server and the reclaimer (a registration), the fifo relay, and an
  epoll's pipe or nested epoll: 224, 252 and 644 KiB with 1, 2 and 16 vCPUs without AMX, 320, 360 and 920 KiB with
  it, against the 128 MiB `memory.max` of jailer-test's limits stage (2 vCPUs) and a VMM's 3.3 to 6.2 MiB working
  set; the working set (docs/COMPATIBILITY.md's VMMMEM) gains at most the one page a thread, to be re-measured: first
  run CI. Threads the callback does not reach: those made before the process's callback runs (two of the test
  binary's, starting in ntdll with the guarantee 0 and 12288 bytes of guard pages) and those the loader never attaches
  (made with `THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH`, or the loader's own workers, which may be started after the
  callback too: one of the test binary's was such a thread or one listed before its attach ran, which CI's
  listing could not tell apart). No TLS callback runs on a thread the loader does not attach, so none of wick's;
  an overflow on one ends as before this fix. The test now reads each thread's TEB SameTebFlags (SkipThreadAttach,
  LoaderWorker; ntdll's public symbols, not documented by Microsoft, its reading checked by the main thread's
  InitialThread bit) and reads a thread without the guarantee again for up to 2 s; one the loader attaches that
  still has none, or one it never attaches that starts outside ntdll, fails the test. Firecracker's own threads, as
  the release build runs a booted guest with 1, 2 and 16 vCPUs, are checked the same way by CI's windows job
  (`vmm-memory-record.py --check-stacks`, VMMSTACK GUARANTEE). First run of both: CI.
- **Windows: a write into memory that a userfaultfd register was moving could be lost, and an access to it at the
  wrong moment could end the process** (since the register moves the memory into sections,
  `windows_mm::uffd_alias`; fixed in the commit that adds this entry). The register copies the mapping's resident
  pages into the new sections, gives the private allocation back and maps the sections in its place. In the copy, a
  write from another thread could land in a private page that was already copied, and be lost with the allocation.
  In the gap before the sections were mapped, an access to the address faulted on nothing and ended the process.
  A system call copying into or out of the memory (counted in flight, `windows_mm::copying`) failed, since the
  kernel's copy takes no exception this process can resolve. Firecracker was not hit: it registers guest memory it
  has just mapped, before any vCPU or device uses it (src/vmm/src/persist.rs `guest_memory_from_uffd`). Now:
  - the register claims the memory against system calls' copies first and waits for those already in their copy,
    as the reclaim's move of a chunk does (`windows_mm::claim_move`);
  - it makes the mapping read-only for the copy, and reads which pages hold memory (the working set) only after
    that, so a write or a first touch just before the move is copied or waits
    (`test_a_write_made_as_a_register_starts_its_move_is_kept`; before, such a page was taken as missing and its
    write lost); a move that fails before the allocation is given back gives
    the runs their protection back (`test_a_failed_registers_move_gives_the_memory_back_writable`); a refusal of
    that ends the process there, named, as a run left read-only would fail a later write or a system call's copy
    far from the cause (`test_a_refused_reopen_after_a_failed_move_ends_the_process`);
  - it marks the memory moving until the register is done, so a faulting access waits and runs again on the
    sections (`test_a_write_during_a_registers_move_lands_in_the_registered_memory`,
    `test_a_register_waits_for_a_call_copying_into_its_memory`; each fails on the code before at the check its doc
    names). The moving mark is one for the process, and `LOCK` keeps a register's mark and the reclaim's apart for
    each one's whole time (`wick_uffd::MovingWindow`, which debug builds check).

  First run: CI.
- **Linux: wick-fsd's confined server kept every descriptor its launcher left open** (from 62067d47, which added the
  confined server, to the commit that adds this entry; never reachable from a guest: nothing in the VMM serves
  wick-fsd yet, virtio-fs staging 8 and 9). It closed nothing it was started with, and a descriptor survives
  `unshare`, `fork` and `pivot_root`; Landlock checks a file's rights when it is opened, not a read or write on one
  already open, and the server's filter allows `read`, `write`, `sendto` and `recvfrom` on any descriptor. So a server
  taken over through its parser could have read or written a host file, or spoken on a socket, that its launcher had
  not marked close-on-exec, outside the share and past every layer. What an ordinary launcher hands down, measured by
  the CI fs jobs' unit-test step's record (docs/design-fs.md §4.2 names the run): on ubuntu-latest and
  ubuntu-24.04-arm the step's shell holds descriptors 142 and 145, a pipe's read end and another's write end, and on
  macos-latest 131 and 140, two `com.apple.netsrc` control sockets, and 143 and 146, pipes; each process the tests
  started inherited them, wick-fsd's unprivileged runs included (sudo closes them, so the root runs did not). Now
  wick-fsd's first step, before it opens anything, closes every descriptor but the standard streams and `--ready-fd`
  whatever its number (`close_range` around `--ready-fd`, or each one of the kernel's `/proc/self/fd` list where the
  kernel has no `close_range`) and reads the kernel's list back, refusing with each descriptor left named, makes
  standard input `/dev/null`, requires `--ready-fd` to be a pipe's write end or a socket and closes it after its byte;
  the confined process then requires its descriptors to be exactly the ones it opened and keeps, from the kernel's
  whole list before `pivot_root` and by number below the soft `RLIMIT_NOFILE` at the read-back, and refuses naming any
  other (`test_descriptors_it_was_started_with_are_closed`: a file, a directory and a socket left open, gone from the
  confined process and its waiting parent as root reads them, with and without `close_range`;
  `test_refused_when_a_descriptor_it_was_started_with_survives`: a `close_range` that said it was done and was not;
  `test_descriptors_held_exactly`; docs/design-fs.md §4.2 and §6.1, steps 3 and 10). On macOS wick-fsd refuses to
  start on every version so far (its confinement is not built yet) and served nothing with what it was started with;
  the first step closes them there too, by the file table's list (`proc_pidinfo`), before the refusal.
- **Linux: wick-fsd started as root: its confined server did not die with wick-fsd, and was dumpable again where
  `fs.suid_dumpable` is 1** (from 62067d47, which added the confined server, to the commit that adds this entry;
  never reachable from a guest: nothing in the VMM serves wick-fsd yet, virtio-fs staging 8 and 9). The server set
  its parent-death signal and not-dumpable before its drop to `--uid`/`--gid`, and a change of the effective ids
  clears the signal and sets dumpable to `fs.suid_dumpable` (`commit_creds`, kernel/cred.c, v6.12, :406 to :413).
  So killing wick-fsd left the confined server running until its connection ended, and on a host whose
  `fs.suid_dumpable` is 1 another process of that uid could have traced it (with 0, the kernel's default, or 2,
  `__ptrace_may_access` refuses a process that is not `SUID_DUMP_USER`, kernel/ptrace.c, v6.12, :342). Now both are
  set again after the drop, with the parent checked alive, and read back with the rest of the confinement once every
  step is done; the server refuses to start otherwise. On the parent tree as root (Docker's linuxkit 7.0.14, aarch64,
  `fs.suid_dumpable` 0) the server outlived its killed parent and `test_the_confined_server_dies_with_its_parent`
  failed; it passed there as uid 65534 (`test_the_confined_server_dies_with_its_parent`,
  `test_the_child_s_parent_death_signal_steps`, `test_the_child_s_dumpable_steps`, docs/design-fs.md §6.1, steps 6
  and 10). A server started without root changes no ids and was not affected.
- **Linux: wick-fsd started as root served with its whole bounding set** (from 62067d47 to the commit that adds
  this entry; never reachable from a guest, as above). It dropped to `--uid`/`--gid` before it emptied the bounding
  set, and the drop from root takes `CAP_SETPCAP` with the rest of the permitted set (security/commoncap.c, v6.12,
  `cap_emulate_setxuid` :1085 to :1098), which each `PR_CAPBSET_DROP` asks for (`cap_prctl_drop` :1235 to :1248); it
  took the `EPERM` that followed as nothing left to drop. Measured on the parent tree as root (Docker's linuxkit
  7.0.14, aarch64): the confined server's `CapBnd` held every one of the kernel's 41 capabilities, its effective and
  permitted sets empty; `test_the_confined_server_dies_with_its_parent` failed there as root and passed as uid 65534.
  Its filter and `no_new_privs` refuse `execve`, the one thing the bounding set limits, so nothing was gained by it.
  Now the set is emptied before the drop, a capability that cannot be dropped is a refusal, and the read-back
  requires it empty (`test_confined_status` reads `CapBnd` 0 for both processes; `test_the_child_s_capability_drop`;
  docs/design-fs.md §6.1, steps 5 and 10).
- **macOS: wick-fsd's exchange (`RENAME_EXCHANGE`) on a volume without one could replace the target with the source and
  report success** (from 4f7f4673, which added the host directory, to ff3174a1, which fixed it; never reachable from a
  guest). The backend learned whether a volume exchanges from the error `renameatx_np(RENAME_SWAP)` gave, and macOS
  26.7.2's msdos (25G332, GitHub's macos-latest; docs/design-fs.md §4.3 names the run) gives none: it reports no
  `VOL_CAP_INT_RENAME_SWAP`, does a plain rename and returns 0, so the target's bytes would have been lost and the guest
  told the exchange was done. Now the backend reads the volume's capability once and refuses an exchange on a volume
  without it with EINVAL before any call (`sys::rename_swap`; `test_stage0_and_renames_on_other_volumes` reads both
  files after the refusal). No guest could reach it: nothing in the VMM serves wick-fsd to a guest yet (virtio-fs
  staging 8 and 9), and stage 0 serves msdos and exfat, which keep no extended attributes, read-only, where a rename is
  EROFS before the backend (docs/design-fs.md §4.3).
- **macOS: a block request on the Async engine, in flight while a balloon or discard pushed its 2 MiB chunk of guest
  memory past half dead, could lose the guest's data or write zeros to its disk** (from 632a5574, which added the
  reclaim of owned guest memory; fixed in the commit that adds this entry). The Async engine's workers copy a
  request with `pread` and `pwrite` straight into and out of guest memory, on threads of their own, while the reclaim
  replaces a chunk's object on the main thread: a read landing in the window went into the freed object, or into the
  fresh one before the live pages were written back over it, and was lost; a write read the fresh object's zeros and
  wrote them to the disk image. From 94bc1d05, which maps the fresh object with no access, such a copy failed with
  `EFAULT` instead, an I/O error to the guest. Only the guest's own memory and disk image were hit, and only when the
  guest itself discarded memory in the chunk its request used. Now each of those system calls counts the owned
  chunks it touches busy for its length (`wick_owned::copying`, from the compatibility libc's copy wrappers), the
  reclaim leaves a busy chunk for a later discard, and a call that arrives during a reclaim waits for it
  (`test_a_pread_in_flight_keeps_its_data_through_a_reclaim`,
  `test_a_pwrite_in_flight_writes_the_guests_data_through_a_reclaim`,
  `test_a_pread_arriving_during_a_reclaim_waits_for_it`, each failing without the count with `EFAULT`; a copy waiting
  for a userfaultfd fill does not block the discard, `test_a_counted_pread_waiting_for_a_fill_does_not_block_a_discard`;
  the count is undone however the call ends, `test_a_copy_that_fails_or_panics_leaves_no_count`). The Sync engine,
  the net device and the other devices copy on the main thread, which is the one that reclaims, and the vCPUs are
  held out by the unmapped stage 2.
- **macOS: on a userfaultfd restore, a guest that inflated its balloon past half of a 2 MiB chunk hung its own VMM**
  (from 632a5574, which added the reclaim of owned guest memory; fixed in the commit that adds this entry). Once a
  chunk of owned guest memory is half dead (balloon or userfaultfd discards), the reclaim moves its live pages into a
  fresh object, and it read every page of the chunk to tell live from zero, under the userfaultfd's lock, which the
  discard holds. A page the handler had not filled yet (missing, `PROT_NONE`) faulted on that read, and the fault
  waited for the handler's copy, which waited for the lock: the VMM's thread and the handler waited on each other for
  good, and the guest's vCPUs then stalled on the chunk. Only the guest's own VMM was hit; no other process, and no
  host memory. Found by Firecracker's `test_uffd.py` (`test_valid_handler`), which hung. Now the reclaim never reads
  a missing page: it stays missing, `PROT_NONE` on the host and out of the guest's stage 2, and uncharged, and the
  fresh object is mapped with no access and each page given back the protection it had
  (`test_a_reclaim_reads_no_missing_page`, which hung until its alarm on the code before;
  `test_owned_reclaim_leaves_missing_pages_out_of_stage_2` under Hypervisor.framework). Mapped read-write, as
  before, the fresh object would also have let the chunk's other missing pages read as zeros with no page fault
  event; the hang came first, so that was not reached. A page that is neither missing nor readable (whose read ended
  the VMM with a fault on the code before) is read under a read access given for the scan and the save only, under
  the quiesce, and keeps its data and its protection
  (`test_a_reclaim_keeps_an_unreadable_pages_data_and_protection`). That part is defensive, not reachable from
  Firecracker: virtio-mem protects and discards whole slots, and slots are whole 2 MiB chunks (vstate/memory.rs
  `update_slot`; memory_hotplug.rs, blocks of at least 2 MiB and slots a multiple of them).
- **Windows: a userfaultfd copy whose commit the job's limit refused in part filled its later pages from the source's start** (from d0fbafae, which made a fill at the limit go on where it was; fixed in the commit that adds this entry). A fill of a reserved section commits its pages first; refused, it fills the pages that fit and goes on with the rest once a reclaim gave room back. The copy's callback was given each part's destination but not its offset into the source, so every part after the first was filled from the source's first bytes: the guest read another page's contents in those pages, with no error. Only a copy that met the job's memory limit in its middle was hit. Now each part is copied from its own offset (`test_a_copy_whose_commit_is_refused_in_part_fills_each_page_from_its_own_bytes`, which scripts the commit's refusals; it failed on the code before).
- **macOS: stage 2 did not follow the host's protection of guest memory** (from the macOS backend's start; its tests
  and this entry, then under "Not at parity yet", in 2e942d5a; fixed in the commit that moved it here). On Linux each
  stage-2 page of a memslot is taken through the host's vma, so a guest access is allowed only as the host's
  protection allows, and an `mprotect` or `munmap` of slot memory invalidates stage 2 before it returns (mm/gup.c,
  v6.12, `check_vma_flags` :1285 to :1287 and :1303 to :1305, no vma :1464 to :1466; mm/mprotect.c :455 to :458;
  mm/vma.c `unmap_vmas` :1095; arch/arm64/kvm/mmu.c :1579 to :1580). Hypervisor.framework maps the physical pages
  behind a host range at `hv_vm_map`, with the slot's permissions, and the backend followed no later change of the
  range's protection or mapping. Measured before the fix (2e942d5a's tests, ignored then), worst first:
  - the guest reached slot memory the host unmapped, and kept the old pages where the host mapped new memory at the
    same address by a hint (`test_a_guest_reaches_new_memory_mapped_where_slot_memory_was_unmapped`: "unmapped:
    Ok(Some(1229782938247303441)), not Err(14)");
  - guest stores landed on memory the host made read-only: after the `mprotect`
    (`test_a_guest_access_the_host_protection_refuses_is_efault`: `Ok(Some(8))` where Linux gives `Err(14)`), while
    a vCPU ran (`test_no_guest_store_lands_after_a_host_mprotect_returned`: "the word was 91141332, then 178463532
    50 ms later"), and in a slot made over read-only memory, whose host page took the store
    (`test_a_slot_over_memory_mapped_read_only_starts_read_only`: "the host's page holds 0x7");
  - the guest executed from a page the host made `PROT_NONE` (`test_a_guest_executes_from_a_host_read_only_page`);
  - a guest access the host refuses, to a page a userfaultfd has not filled, posted an event
    (`test_a_refused_access_to_a_missing_page_posts_no_event`);
  - the guest read a page the host made `PROT_WRITE` alone before it wrote it
    (`test_a_write_only_host_page_is_readable_by_the_guest_after_its_write`).

  Now every `mprotect`, `munmap` and `mmap` of the compatibility libc tells the backend after it returned
  (`wick_guest::Hooks::protected`), and the backend reads the range's protection, with the userfaultfd's
  registrations, under the VM's memory lock and brings stage 2 to it: a page whose mapping went is unmapped, one
  mapped anew is mapped with the new pages, the others get their permissions; each run of pages is mapped with its
  final permissions, none at all included, never more for a moment. A protection value cannot tell a page from the
  page that replaced it, so each call also says whether the range's mappings were replaced (`munmap`, and a new
  mapping not placed by `MAP_FIXED`, which can only be where nothing was; a `MAP_FIXED` one is followed as a
  replacement): then every slot page of it that was in stage 2 is unmapped first, whatever its protection reads now,
  and the read decides whether the pages there now are mapped. Memory unmapped and mapped again by another thread
  before the `munmap`'s hook ran is so reached anew, in either order of the two hooks
  (`test_memory_mapped_where_slot_memory_was_unmapped_before_its_hook_reaches_the_guest`). The bound that lets an
  `mprotect` outside every slot skip the lock is stored only under the memory lock, so a slot made while another is
  removed still takes a protection changed meanwhile
  (`test_a_slot_made_while_another_is_removed_takes_a_protection_changed_meanwhile`). A stage-2 protect that takes a
  permission away and fails ends the process with a line naming the range, the flags and the return, as a failed
  unmap does; one that gives a permission and fails is `KVM_RUN`'s error, never retried silently. No test can make
  Hypervisor.framework fail a protect, so this rule is not shown failing. The stage-2 calls are made by runs of
  contiguous pages, one call a run, also across pieces that separate calls mapped and over part of one mapping
  (`test_one_change_across_pieces_mapped_apart_reaches_each`). The memory lock is held for the whole call, and a
  vCPU that faults meanwhile waits for it: over 1 GiB of a slot, every page in stage 2, optimized as a release
  build (M1 Pro, macOS 27.2, three runs), an `mprotect` held it 3.7 to 4.0 ms and an `munmap` 28.9 to 30.3 ms, of
  which one `hv_vm_unmap` of the GiB took 25.7 to 27.0 ms; page by page it was 31 to 33 ms and 36 to 51 ms
  (`test_the_memory_lock_held_by_a_hook_over_a_gib`, run by name). No running vCPU is made to leave its run, as
  none is on Linux on arm64: KVM's stage-2 unmap ends in a broadcast TLB invalidation that is complete on every CPU
  when it returns (arch/arm64/kvm/hyp/pgtable.c, v6.12, `stage2_unmap_put_pte` :846 to :867; hyp/vhe/tlb.c
  `__kvm_tlb_flush_vmid_ipa` :92 to :120, `tlbi ipas2e1is` then `dsb ish`), and arm64's
  `kvm_arch_flush_remote_tlbs` (mmu.c :169 to :173) returns 0, so virt/kvm/kvm_main.c :349 to :350 sends no
  `KVM_REQ_TLB_FLUSH` and kicks no vCPU. What is relied on here is that `hv_vm_protect` and `hv_vm_unmap` have
  invalidated the running vCPUs' stage-2 translations when they return; hv_vm.h does not say so. It rests on the
  same broadcast invalidation as Linux's, and on the host's own safety: macOS takes pages from a running guest
  (pageout, a page freed by a host `munmap` and reused) through the same stage-2 removal, and one that reached a
  running vCPU late would let a guest write a page the host had given to someone else. Measured on macOS 27.2, M1
  Pro, with the vCPU in a loop that makes no exit of its own, so that a change taken up only at the next entry
  would never have stopped the stores: no store landed after the `mprotect` returned, and the run left
  `hv_vcpu_run` once only, for the refused store, in the 50 ms round and 300 rounds more
  (`test_no_guest_store_lands_after_a_host_mprotect_returned`); none landed on the old page after a discard
  returned, the run leaving `hv_vcpu_run` for nothing but faults until the test's own kick
  (`test_no_guest_store_lands_on_old_pages_after_a_discard_returned`). Not measured on another macOS version or
  chip: CI's runners have no Hypervisor.framework, so these runs are this Mac's alone; both tests are on
  docs/PORTING.md's list of what to measure again on a new macOS major. A guest abort is checked against the page's host protection before a userfaultfd is asked, so a refused
  access is `EFAULT` from `KVM_RUN` and posts no event. A write or execute protection without read, which XNU widens
  with read (bsd/kern/kern_mman.c, `mmap` :349 to :351, `mprotect` :1251 to :1253), is read as it was asked, as a
  vma keeps it (`test_a_protection_xnu_widens_reads_as_asked`). Every test above passes, the mprotect one over its
  50 ms round and 300 rounds more; also `test_the_protection_stored_last_is_the_one_the_host_has` and
  `test_a_slot_made_while_an_mprotect_runs_takes_its_protection` (each fails when the protection is read before the
  memory lock), `test_a_page_mapped_with_no_permission_faults_and_takes_its_permissions_later`,
  `test_no_guest_store_lands_on_old_pages_after_a_discard_returned` and
  `test_an_mprotect_of_memory_in_no_slot_takes_no_vm_lock` (an mprotect outside the slots costs two atomic loads).
  What stays different:
  - Only the compatibility libc's calls are followed; a call of the system's own library on guest memory (Rust
    std's, a framework's) is not, and Firecracker makes its calls on guest memory through the compatibility libc
    (docs/PORTING.md, the `libc` row).
  - The backend's own store to guest memory (the stolen-time record, `write_guest`) checks the page's protection and
    then stores, not in one step: a host `mprotect` or `munmap` of that page on another thread can land between the
    two, and the store then takes the host's fault and ends the VMM, where Linux's `put_user` returns `EFAULT`. It is
    never a refused store that lands. Reaching it needs the VMM to `mprotect` or `munmap` guest RAM in a live slot
    while a vCPU runs, which Firecracker does not (below; its `MAP_FIXED` replacement is waited for, as a guest
    fault waits for it).
  - The memory lock is held over the whole range of a call. Linux's MMU notifier holds `mmu_lock` for write over
    the range too (virt/kvm/kvm_main.c, v6.12, :646; a stage-2 fault takes it for read, arch/arm64/kvm/mmu.c
    :1624), but lets a waiter in between blocks of it when the call may block (mmu.c `stage2_apply_range` :56 to
    :80, `cond_resched_rwlock_write` :76; a block is 32 MiB with 16 KiB pages, 1 GiB with 4 KiB). Here a vCPU's fault
    waits for the whole call: about 4 ms for an `mprotect` of 1 GiB and 30 ms for its `munmap` (above).
  - A private mapping of a file is a copy of the file made at `mmap` (XNU maps a file without `MAP_SHARED` with
    copy, bsd/kern/kern_mman.c :880 to :882): a later change to the file never reaches a page the mapping has not
    written, where on Linux it does until the mapping writes the page (mm/memory.c, v6.12, `do_read_fault` :5431,
    `do_cow_fault` :5433); the mapping's own writes stay out of the file on both
    (`test_a_private_file_mapping_is_a_copy_made_at_mmap`). Firecracker maps a snapshot's memory file so, and
    upstream calls a change to that file while the VM runs undefined behaviour
    (lib/firecracker/docs/snapshotting/snapshot-support.md, "must be considered immutable"): the case lost is one
    upstream excludes, and here the guest is the more isolated from the file. A memfd (a shared memory object)
    maps shared only; its private mapping is `EINVAL` with nothing changed
    (`test_a_private_mapping_of_a_shared_memory_object_is_refused`, docs/PORTING.md row 10).
  As Linux already before: a guest store to a read-only memory slot exits as MMIO, also with the slot's memory
  `PROT_READ` (`test_a_store_to_a_read_only_slot_is_still_mmio`). Firecracker reached none of the cases above, as read from the
  code: it changes the protection of guest memory only outside a live slot (virtio-mem's `update_slot`,
  lib/firecracker/src/vmm/src/vstate/memory.rs :701, makes a slot readable and writable before it adds it and
  `PROT_NONE` after it removes it; `register_memory_region`, vstate/vm.rs :497, protects only the slots it does not
  add); it maps a read-only pmem's memory `PROT_READ` in a read-only slot (devices/virtio/pmem/device.rs :192 to
  :195 and :335 to :339); it replaces hotplugged memory's pages by `MAP_FIXED` (memory.rs :797 to :808), which is
  followed; and it unmaps guest memory at teardown, after `Vmm`'s drop has ended the vCPU threads (lib.rs :794 to
  :798) and the VM's descriptor is dropped (`VmCommon`, vstate/vm.rs :81, before the guest memory at :84). No other
  process can make these changes to the VMM's memory, and a compromised VMM can read and write guest memory
  directly, so it gains nothing by them. The compatibility layer is held to Linux's behaviour all the same, so that
  code which relies on the host's protection of guest memory behaves here as it does on Linux.
- **Windows: `munmap` and `mmap(MAP_FIXED)` of userfaultfd-registered memory left the registration** (from the
  Windows userfaultfd backend's start; its tests and this entry, then under "Not at parity yet", in 5859a449; fixed
  in the commit that moved it here). On Linux the registration belongs to the vma and goes with it (mm/vma.c, v6.12,
  `do_vmi_align_munmap` :1332; mm/mmap.c `__mmap_region` :1361). On Windows both calls changed the mapping and left
  the range registered over memory that was gone or new. Measured on Windows Server 2022 20348 before the fix:
  - a fill (`UFFDIO_COPY`, `UFFDIO_ZEROPAGE`) into memory mapped anew ended the VMM with an access violation
    (0xC0000005), where Linux's is `ENOENT`: the page was committed at the address, by then the new mapping, and
    written through the old range's alias, whose page was never committed;
  - unmapped memory was opened: a fill into a page unmapped from a registered range filled it, and once the
    userfaultfd was released the first access to such a page committed it read-write;
  - an access fault on memory mapped anew waited as a userfault, and a thread waiting on a page then unmapped
    waited again once woken;
  - memory mapped anew could not be registered (`EBUSY`), and its discard made it missing and closed;
  - a fill whose destination held a page unregistered from the middle of a range filled the pages before it, where
    Linux's is `ENOENT` with nothing filled.
  Firecracker unmaps its registered guest memory whole at teardown, while its userfaultfd is open
  (vstate/memory.rs:308, before the VM's `uffd`, vstate/vm.rs:84 and :95); fills after that would come from its
  handler. Now `munmap` and `MAP_FIXED` hold the userfaultfd's lock from before the change until the pages they took
  are in no registration, so a fill or a release arriving in between waits and then finds none
  (`test_an_unmapping_and_its_unregistration_are_one_step`); a fill whose destination holds a page in no
  registration is `ENOENT` with nothing filled; a waiter waits on its userfaultfd, whose wake or release ends the
  wait; a range with no page left registered is freed
  (`test_memory_unmapped_while_registered_leaves_no_registration_behind`,
  `test_memory_replaced_while_registered_is_in_no_registration`,
  `test_a_discard_of_memory_replaced_while_registered_is_ordinary`,
  `test_a_waiter_on_memory_mapped_over_is_woken_by_its_userfaultfd`,
  `test_a_waiter_on_unmapped_memory_takes_its_own_fault_once_woken`, `test_a_fill_of_an_unregistered_page_is_enoent`,
  `test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is`). A change of memory in no
  registration (`munmap`, `MAP_FIXED`, `mprotect`, a discard) and a register of the same memory are ordered by two
  sequentially consistent counts, as on macOS (the entry below), so a register racing one finds the memory as the
  change left it (`test_a_register_racing_a_munmap_leaves_nothing_registered`,
  `test_a_register_racing_a_map_fixed_registers_the_new_memory`,
  `test_a_register_racing_an_mprotect_keeps_its_pages_missing`, `test_a_register_racing_a_discard_fills_the_new_pages`);
  before, per call, from the commit that brought its check without the userfaultfd's lock (whether the call's range
  touched a registered range), a register of the same memory that started between that check and the call went on
  beside it: a discard (`MADV_DONTNEED`, `MADV_FREE`), from b0dfb35b, the first Windows userfaultfd, already public
  (`discarding`'s check and `madvise`'s `wick_uffd::active()`): the register took a page the discard then emptied for
  resident, so it read zeros and was not missing; `mprotect`, from 5d08b98a, already public
  (`mprotect_registered`'s `REGISTERED == 0`): the register's view put a page's protection back to read-write;
  `munmap` and `mmap` with `MAP_FIXED` did not look at registrations at all before this fix (the defect above). With
  the counts taken out, the race tests fail so: "the discarded page is not missing", "the protection asked: Some(4)"
  (`PAGE_READWRITE`), "registered over memory that is gone (Ok(()))", "the new memory is not what was registered".
  And a register keeps the protection `mprotect` gave each page, where before it mapped the memory read-write
  (`test_a_register_keeps_the_protection_mprotect_gave`).
  Each of these tests fails under the mutation that takes its part of the fix out (docs/ARCHITECTURE.md, "Memory
  calls on registered memory"). What stays different is under "Not at parity yet".
- **Windows: a thread pool could keep a jailed process running after one of its threads used up its stack**
  (shipped since the jailer's job got `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, 5579ea53; fixed in 50021416 for
  a stack used up, and for every other unhandled exception by the last unhandled-exception filter that followed it).
  In such a job Windows Error Reporting is not called, and an unhandled exception's end is left to whoever called the
  unhandled-exception filters. A pool thread's stack overflow, which the stack filter passed on, was taken by its
  pool, which went on running callbacks, and the process exited 0: measured in the libc crate's test process on
  Windows Server 2022 20348 and 2025 26100 (`test_a_stack_overflow_at_the_reserves_end_is_still_one`, its pool child
  in a job of the jailer's limits). An access violation, an illegal instruction
  and a software exception, continuable or not, were not taken so: each ended the process with its code on every
  kind of thread, pool and job included (`test_an_unhandled_exception_ends_the_process_with_its_code`, run before its
  fix). Now the stack filter, and below every filter the last one (`windows_mm::last_filter`, installed before `main`
  in all three binaries), write a line naming the exception and, in such a job, end the process with its code; out
  of such a job Windows Error Reporting ended it, with its dump, until the next entry's fix. The last filter keeps the filter it
  replaces, the Visual C++ runtime's, and calls it after its line, so an unhandled C++ exception still ends as the
  runtime ends it (`terminate()`, exit 0xC0000409), jailed or not
  (`test_a_cxx_exception_nothing_catches_ends_through_the_runtimes_filter`). Per process kind:
  - the jailer: not in such a job, so the defect did not reach it; measured with an access violation and a
    breakpoint injected into a running jailer.exe (a remote thread), two runs each, debug and release builds, on
    Windows Server 2022 20348: the line, then Windows Error Reporting ended it with the exception's code (0xC0000005,
    0x80000003), and its jailed child ended with it. In both builds the last filter's `.CRT$XCU` initializer is in
    the image's initializer table after the runtime's `pre_cpp_initialization`, and the running jailer's last filter
    holds the runtime's `__scrt_unhandled_exception_filter` as the filter it replaced (cdb). It has pool threads at
    rest (three `ntdll!TppWorkerThread`, cdb).
  - the VMM (firecracker.exe in the jailer's job): its pool threads run polling's wait callbacks
    (`RegisterWaitForSingleObject`, crates/compat/polling). Before the fix its stack filter passed an overflow on to
    vmm-sys-util's filter, which runs the SIGSEGV handler Firecracker registers, on the overflowed stack; whether a
    jailed VMM kept running is not measured. The binary-level measurement is not run: firecracker.exe did not start
    on a host without the Windows Hypervisor Platform, such as the test VM it was tried on (`STATUS_DLL_NOT_FOUND`
    before `main`: since 527070ed it imported `WHvAdviseGpaRange` at load time, which 03bc63bc loads at first use,
    `test_no_whp_dll_is_imported_at_load_time`); it runs there now and, with no platform, `Kvm::new` fails with a
    line naming the missing feature and the fix before `ENODEV`
    (`test_kvm_new_fails_with_enodev_where_the_platform_is_absent`), so the stack measurement needs a host with the
    platform and has not run yet. The libc and vmm-sys-util code it runs is the tests' above.
  - the API process: the same polling callbacks on pool threads. Not run, for the same reason, and not yet since.

- **Windows: a thread pool could keep an unjailed process running after one of its threads used up its stack**
  (since 50021416, which left the end out of a jail to Windows Error Reporting; fixed by the commit that adds this
  entry). Out of a job of the jailer's limits the stack filter and the last filter passed the exception on
  (`EXCEPTION_CONTINUE_SEARCH`), expecting Windows Error Reporting to end the process. Under
  `SEM_NOGPFAULTERRORBOX`, which a process inherits from its parent (Learn, SetErrorMode), the system's
  `UnhandledExceptionFilter` invokes no Windows Error Reporting and returns `EXCEPTION_EXECUTE_HANDLER`, and a
  thread pool's worker, which calls it from its own exception filter (`ntdll!TppWorkerThread$filt$5`,
  `TppWorkerpInnerExceptionFilter`, on Windows Server 2022 20348 then `TppExceptionFilter`: FILTERREC, named by cdb
  with Microsoft's public symbols), took a stack overflow so and ran its next callback on the overflowed thread,
  the process exiting 0. CI's runner gives its children error mode 3: CI run 43881982686's two libc failures
  (`test_a_stack_overflow_at_the_reserves_end_is_still_one` alone, and
  `test_a_job_nested_in_one_that_dies_on_unhandled_exceptions_ends_by_its_own_limits` in a job without the flag);
  on Windows Server 2022 20348 and 2025 26100 at error mode 3, exit 0 in 22 ms, the next callback on the same
  thread, where error mode 0 ended 0xC00000FD through Windows Error Reporting; an access violation was never taken
  so. Now both filters end the process themselves, for every exception they get, at every error mode: in a job of
  the jailer's limits by `TerminateProcess` with the exception's code, as before; out of one by
  `RaiseFailFastException` with the exception's own record and context, which bypasses every handler and ends the
  process with that code, invoking Windows Error Reporting if it is enabled (Learn, RaiseFailFastException). Of the
  filter the last one replaced (the Visual C++ runtime's) only `EXCEPTION_CONTINUE_EXECUTION` is passed on. The
  three tests run each child at error mode 0 and 3 and assert the exception's own code and that the pool's next
  callback did not run; they failed before the fix at error mode 3 on both hosts (the pool's overflow, alone and in
  a job without the flag, nested or not: exit 0) and pass after it, and an access violation on a pool thread is the
  control (0xC0000005 before and after; with the end given no record, the mutation, every case ends
  STATUS_FAIL_FAST_EXCEPTION, 0xC0000602, the control too). `RaiseFailFastException` ended the process with the
  record's code with as little as 6784 to 9136 bytes left above the reserve's low end on each kind of thread
  (FAILFASTSTACK; below that the record's own 1 KiB frames faulted first); a pool thread enters the filter with
  9136 bytes left, a Rust thread, with its 20 KiB guarantee, with 22480. Code of wick's and Firecracker's that runs
  on a thread pool's thread, read from the code:
  - the VMM and its API process: polling's wait callback (crates/compat/polling, `WaitHandle`'s callback of
    `RegisterWaitForSingleObject`: it takes the source's lock, marks it idle and posts a completion packet), for
    each eventfd, console, pipe, nested epoll and other waitable handle an epoll watches (crates/compat/vmm-sys-util
    windows/epoll.rs); nothing else of either submits work to a pool;
  - the jailer: none (it has no epoll); its pool threads run the system's work only.
  A report out of a jail is what Windows Error Reporting makes of any crash on that host: where the host has its
  dumps enabled, a dump of an unjailed VMM holds the guest's memory, as a Linux core of Firecracker does where the
  host allows cores; in a jail none is made (the job's flag: no Windows Error Reporting).

- **Windows: a userfaultfd could be refused to a process whose pid a killed process had used** (since b0dfb35b,
  which made the userfaultfd kernel side; fixed by the commit that adds this entry). Its two ends are an AF_UNIX pair
  made through a listener on `%TEMP%\wick-uffd-<pid>-<n>.sock`, and the path was removed only after the pair was
  accepted. A process that died before that left the path, and a later process with the same pid was refused the
  bind (WSAEADDRINUSE) and so its userfaultfd, where Linux's `socketpair` cannot fail so. Seen on Windows Server 2022
  20348 after a debugger ended a test process; reproduced by leaving such paths
  (`test_a_userfaultfd_is_made_over_paths_a_dead_process_of_this_pid_left`, failing before the fix). Now the path is
  removed as soon as the connection is made, before it is accepted, so it exists only from the bind to the connect.
  A path of this process's pid left by a dead one is removed before the bind; nothing live can hold that name.
  The accepted end must be this process's own connection (`SIO_AF_UNIX_GETPEERPID`), or the pair fails with a line
  naming the path. Any writer of the temporary directory could connect while the path existed and be the end
  accepted, which was not checked before; no such connection was seen. The behaviour this relies on is measured on
  the host (`test_af_unix_paths_and_abstract_addresses_on_record`): a connection queued on the listener is accepted
  after its path is deleted, and both ends report this process's pid.
- **macOS: a virtio-mem slot plugged after a restore from a userfaultfd let the VMM read memory the handler had not
  filled.** On `main` from 6c4320c5 (the compatibility `libc`, with its userfaultfd) to the commit that brought
  `libc::wick_uffd::protecting`. Path: a microVM restored with `mem_backend` `Uffd` registers every guest region
  with the userfaultfd, the hotplug region too (persist.rs `guest_memory_from_uffd`); an unplugged slot is made
  `PROT_NONE` and a plugged one `PROT_READ | PROT_WRITE` (vstate/memory.rs `GuestMemorySlot::protect`). That
  `mprotect` went to macOS as it was, and a missing page, kept `PROT_NONE` so that a host access faults to the
  handler, became readable and writable: the VMM's own accesses there (its device emulation) read zeros with no
  fault, and a later fill of the page, still missing to the userfaultfd, overwrote what the VMM had written. The
  guest's own accesses still went to the handler, as a fill alone maps a page into stage 2 (`libc::wick_guest`).
  Effect: the integrity of the guest's data in plugged memory, not the host's isolation. Fixed: `mprotect` of
  registered memory keeps missing pages inaccessible and gives each the protection asked once it is filled or no
  longer registered, as Linux's mprotect leaves the registration as it is (docs/ARCHITECTURE.md, "Memory calls on
  registered memory"; `test_plug_after_a_uffd_restore`,
  `test_a_slot_plugged_after_a_uffd_restore_still_faults_host_accesses`).
- **macOS: a fill after a discard of a registered page that was not writable ended the process by SIGBUS** (from
  fc1d7a42, which made a discard remap the userfaultfd's alias over the new pages, to the commit that brought
  `libc::wick_uffd::protecting`). The remap gives the alias the new pages' protection, and every fill writes through
  the alias: after `mprotect` to `PROT_READ` of filled registered pages and a `MADV_DONTNEED` of them, the handler's
  next fill there ended the process by SIGBUS (measured, before the fix:
  `test_a_filled_page_takes_the_protection_asked_while_it_was_missing`, "signal: 10, SIGBUS"). Firecracker reaches it:
  after a restore through a userfaultfd, a virtio-mem unplug of a whole slot makes it `PROT_NONE` and then discards it
  (devices/virtio/mem/device.rs: `update_slot` before `discard_range`), so the alias of its filled pages became
  `PROT_NONE`; once the slot was plugged again, the handler's fill of a page the guest touched ended Firecracker by
  SIGBUS. Those calls in that order are measured at the libc's level
  (`test_a_slot_unplugged_and_plugged_again_is_filled`, SIGBUS with the alias left as the remap made it), not in a
  VM. Then the alias was made read-write after the remap (`discarding`); there is no alias now: each fill writes
  through a mapping of the pages made read-write for it and taken away after it (`fill_view`), and gives the page the
  protection asked.
- **macOS: a userfaultfd's release after its registered memory was unmapped changed whatever was mapped there since**
  (from 6c4320c5, the compatibility `libc` with its userfaultfd, to the commit that brought
  `libc::wick_uffd::unmapping`). `munmap`, and `mmap` with `MAP_FIXED`, left the registration in place, where Linux's
  goes with the vma. Firecracker unmaps its registered guest memory at teardown while the VM's userfaultfd is still
  open (the guest regions' drop, lib/firecracker/src/vmm/src/vstate/memory.rs:308, `guest_memory` dropped before
  `uffd`, vstate/vm.rs:84 and :95), and the userfaultfd's release then made the range's old missing pages read-write
  on whatever was mapped there by then in the same process, such as another thread's new stack guard or a `PROT_NONE`
  reservation: measured, a `PROT_NONE` mapping made in the hole was read-write after the release
  (`test_a_release_after_the_memory_was_unmapped_leaves_a_new_mapping_as_it_is`, "left: (3, 3) right: (0, 0)" before
  the fix), not measured in a VM. The window was from `guest_memory`'s drop to `uffd`'s, or longer while the handler
  held its copy of the userfaultfd (read from the code). The same left memory mapped over registered memory taken for
  the old (missing pages, a discard making it missing), which no Firecracker path reaches, as read from the code. Now
  the pages leave the registration in the same step as the change of the mapping, under the lock every change of the
  registrations takes (`test_an_unmapping_and_its_unregistration_are_one_step`,
  `test_memory_unmapped_while_registered_leaves_no_registration_behind`, docs/ARCHITECTURE.md, "Memory calls on
  registered memory").
- **macOS: `MADV_DONTNEED` took private file mappings and anonymous memory for each other** (from 6c4320c5 to the
  commit that brought `MADV_FREE` as Linux takes it). It told a private file mapping by the VM entry's file pager and
  shadow, and asked `proc_regionfilename`, which names the next file mapping at or after the address, whether a file
  was under it. Three cases went wrong (macOS 27.2): a private file mapping with some pages copied went to macOS's own
  `MADV_DONTNEED`, which keeps the copies (measured by a C probe), where Linux's show the file again; one with every
  page copied, whose entry macOS then reports with no file pager and no shadow (measured), was taken for anonymous
  memory and read as zeros; and anonymous memory with a copy-on-write copy, followed by any file mapping, was refused
  with `EINVAL` (`test_madvise_dontneed_of_anonymous_memory_with_a_copy_reads_zeros`, "left: -1 right: 0" under the
  old check).
  Firecracker reaches none of them: it remaps a private file mapping instead of discarding it (`discard_range`,
  lib/firecracker/src/vmm/src/vstate/memory.rs:745) and makes no copy of its anonymous memory, as read from the code.
  Now the file is found through the entry's own vnode (`PROC_PIDREGIONPATHINFO`) and copied pages through `mincore`:
  a piece holding one is `EINVAL` with nothing changed, as macOS has no call that shows the file again
  (`test_madvise_dontneed_of_a_private_file_mapping_with_copied_pages_is_einval`, docs/PORTING.md). The new calls
  (`proc_info` for this process, `mincore`) run under Firecracker's run-phase profile, with `MADV_DONTNEED` and
  `MADV_FREE` of anonymous and registered memory, and the child ends by its own exit
  (`test_discards_run_under_the_run_phase_profile`, on macOS 15 and 26 as well: COMPATIBILITY's System call filter
  row; with `mincore` out of the profile's list the sandbox kills it).
- **macOS: a register racing a change of memory in no registration could register the memory the change then
  replaced** (to the commit that brought `unlocked_change`). Each of these calls first checks, without the
  userfaultfd's lock, whether its range touches a registered range, and runs without the lock when it does not; a
  register of the same memory that started between that check and the system call registered the old memory, and
  the change then went on as if nothing were registered. Per call, from the commit that brought its check:
  - a discard (`MADV_DONTNEED`, and `MADV_FREE` since it takes that path), from 6c4320c5, the first compatibility
    `libc`, already public: the new pages were present under the registration and a fill went to the old ones
    through the alias;
  - `mprotect`, from 56082145 (before it, `mprotect` did not look at registrations at all, the plugged virtio-mem slot
    defect above): a missing page was left accessible;
  - `munmap` and `mmap` with `MAP_FIXED`, from 0dc4cb4b (before it, neither looked at registrations, the userfaultfd's
    release defect above): after an `munmap` the range stayed registered over memory that was gone, which a later
    release would open; after a `MAP_FIXED` mapping the new pages were present and a fill went to the old ones.
  On Linux the mm's lock orders the two. Firecracker does not reach it, as read from the code: its only register is
  of guest memory it has just made and no other thread has yet (lib/firecracker/src/vmm/src/persist.rs:563 and
  :582). Now the change and the register are ordered by two counts, each sequentially consistent, so that at least
  one sees the other: the register waits for the changes already running without the lock, and a change that sees a
  register takes the lock (`test_a_register_racing_a_munmap_leaves_nothing_registered`,
  `test_a_register_racing_a_map_fixed_registers_the_new_memory`,
  `test_a_register_racing_an_mprotect_keeps_its_pages_missing`, `test_a_register_racing_a_discard_fills_the_new_pages`;
  each fails with neither count; docs/ARCHITECTURE.md, "Memory calls on registered memory").
- **Windows: a host thread's access to a userfaultfd page unregistered and resolved by another thread before the
  access's handler looked ended the process with an access violation, when the userfaultfd was made before any lazy
  memory** (the order from 74108a7b, which added the lazy-memory handler at a register; the case from a1e58baa,
  whose released records let another thread resolve the page in between; found by the hook test asked for after the
  macOS fault-after-fill race). The lazy-memory code and the userfaultfd each added a vectored exception handler,
  first in the chain, so the one added last ran first. With the userfaultfd made first, the lazy-memory handler
  looked at the page while it was registered and missing (not its to resolve) and the userfaultfd's looked after an
  unregister and the other thread's write: no longer registered, so it passed the exception on and the process ended
  with 0xC0000005, where Linux's fault finds the page present and the access runs again
  (`test_a_host_access_that_faulted_before_an_unregister_runs_again`, its child with the create first: 0xC0000005
  on bfccf902, Windows Server 2022 20348 and 2025 26100). Firecracker's restore maps its guest memory (`MAP_NORESERVE`) before it makes the
  userfaultfd (persist.rs :557 to :589, memory.rs :186), the order that passed. Now one handler
  (`windows_mm::on_exception`), added by whichever of a lazy mapping, a create or a register comes first, runs its
  steps in one order: a stack overflow's retry; the userfaultfd's wait for a move or a fill; the released and lazy
  resolve; and one last check that re-runs an access to memory of ours (registered, held by a released record, or
  lazy) that its protection allows now, every other violation going on at once as before. Both orders of first use
  pass, and so does the mirror, the page resolved between the userfaultfd's step and the resolve
  (`test_a_host_access_that_faulted_on_a_released_page_resolved_meanwhile_runs_again`; 20348 and 26100).
- **macOS: a host thread's fault on a missing page that a fill or an unregister resolved before the handler read it
  ended the process** (from 6c4320c5, the macOS userfaultfd's start, to the commit that brought `may_retry`). The
  userfaultfd's SIGBUS and SIGSEGV handler handled a fault only while the page read as missing. A fill and an
  unregister make the page accessible first and then clear its bits, so a thread whose access faulted before that
  and whose handler read the page after was handed to the previous handler, Firecracker's, which ends the VMM; Linux's
  fault there finds the page present, or the vma no longer registered, and maps it. Found by reading the code;
  reaching it needs two VMM threads touching one missing page at once, not measured in a VM. Now such an access is
  retried when the page's host protection allows it and, for a registered page, its asked protection does too
  (`test_a_fault_resolved_before_its_handler_reads_the_page_is_retried`: the fill and both unregisters, completed
  by a hook between the fault and the handler's read, or between the handler's read and `fault`'s own, and a store
  the asked protection refuses still handed on). The retries of one address by one thread are bounded at two while
  nothing changes (`test_retries_of_a_fault_with_nothing_changed_are_bounded`; threads keep their own counts,
  `test_live_threads_spread_over_the_retry_entries`, `test_threads_in_different_retry_entries_keep_their_counts`);
  while other threads change the ranges, the count starts again after each change. So a fault the rule reads wrongly
  (a SIGBUS on a mapping whose protection allows the access: a file mapping past its end, a pager's error) is
  retried twice after each fill for as long as fills go on, during an on-demand restore, and ends when they stop,
  where before, and on Linux, it ended at once. Not as Linux either: an address in no registered range whose
  protection came to allow the access between the fault and the handler's read (an `mprotect` on another thread)
  is retried, where Linux delivers the signal; the handler cannot tell it from a page an unregister freed.
- **macOS: a userfaultfd page fault event whose waiter was woken before it was read was still read** (from 6c4320c5,
  the macOS userfaultfd's start; this entry, then under "Not at parity yet", in 7d4d9645; fixed in the commit that
  moved it here). On Linux a wake (an unregister, a `UFFDIO_COPY` or `UFFDIO_ZEROPAGE` that wakes, `UFFDIO_WAKE`, the
  release) takes each waiting fault it wakes off the queue, read or not (v6.12 fs/userfaultfd.c
  `userfaultfd_wake_function` :141, `__wake_userfault` :1166 to :1176). Here the event was a record written into the
  userfaultfd's socket at the fault, and the wake left it there. Upstream's on-demand handler reads every event into
  a batch (examples/uffd/on_demand_handler.rs :80) and unregisters a page on its remove event (:93 to :94); a fault on
  that page posted before the unregister and read in the next batch was served with a `UFFDIO_COPY`, `ENOENT`, and the
  handler panics on that error (uffd_utils.rs :169 to :187): a guest touching pages its balloon was inflating could
  end its own restore's handler (test_uffd.py :100 to :109). Read from the code, not observed in a VM. Now each
  userfaultfd has a waiter mirror, and the `userfaultfd` crate returns a page fault only while its waiter waits
  (`test_an_unread_fault_unregistered_is_not_read`, `test_an_unread_fault_filled_with_a_wake_is_not_read`,
  `test_an_unread_fault_woken_is_read_once_as_its_new_fault`, `test_a_record_written_after_its_wake_is_not_read`,
  `test_a_blocking_read_waits_past_a_woken_waiters_record`; the first three and the last failed before the change;
  `test_an_unread_fault_filled_without_a_wake_is_still_read` passes on both). What the mirror is, as a channel:
  - It is a POSIX shared memory object of one page (256 words, one per waiter slot), which the VMM maps read-write
    and each reader maps read-only. Its direction is VMM to handler only: the VMM never reads what a reader could
    write, and a reader cannot write it. The descriptor a reader gets (`OP_MIRROR` on its request channel) is opened
    read-only, so it maps no writable view (`EPERM`) and no private one (`EINVAL`), and its read-only mapping cannot
    be made writable (`EACCES`), as xnu-12377.121.6 bsd/kern/posix_shm.c `pshm_mmap` refuses a write to a descriptor
    opened without `FWRITE` and takes write out of the mapping's maximum protection (:828 to :832), and refuses a
    mapping not `MAP_SHARED` (:823 to :825) (`test_the_mirror_a_reader_gets_is_read_only`).
  - What a compromised VMM can do with it: make the handler drop or return page fault events, which it can already
    do by writing records (or none) into the userfaultfd's socket. The reader checks a record's slot against the
    table before it reads (`EBADMSG` past it, `test_a_tag_past_the_mirror_is_an_error`), maps only a descriptor of the
    table's size (`test_a_mirror_of_another_size_is_refused`), and fails the read if the mirror cannot be set up,
    never reading without the check (`test_a_kernel_side_without_the_mirror_fails_the_read`: a kernel side that
    predates the mirror). A reader that predates the mirror fails on the first page fault, whose event type changed
    (`test_a_page_fault_record_is_no_type_a_reader_before_the_mirror_decodes`).
  - The Seatbelt profile is unchanged: the object is named as the compatibility memfd names its objects
    (`/fcm.<pid>.u` and 16 random hex digits since the entry below), which the profile's `shm_rule` already allows
    (overlay/vmm/ext/sandbox.rs :960), and is unlinked at once. Firecracker makes its userfaultfd at the snapshot load, after the API thread's filter has put
    the setup profile on (`vmm::seccomp::apply_filter`), and its handler reads in the run phase
    (`test_a_userfaultfd_and_its_mirror_work_under_the_profiles`, run by the seatbelt jobs on macOS 15 and 26).
  - One mirror a userfaultfd (at most 16, `MAX_CTX`), given back at its release on both sides: the VMM unmaps it and
    closes its descriptor once no thread uses it, and a reader unmaps its view when it is dropped
    (`test_a_userfaultfds_mirror_is_given_back_at_its_release`, 48 made and released, descriptors and mirrors as
    before and each mapping gone; `test_a_readers_mirror_goes_with_it`). The release's wait for the threads using
    the userfaultfd also closes a race of its own: before, a waiter's write of its record could reach a kernel end
    the release had closed meanwhile, or a descriptor that had taken its number (found by reading).
- **Windows: a userfaultfd page fault event whose waiter was woken before it was read was still read** (from
  b0dfb35b, the Windows userfaultfd's start; found by reading, not observed in a VM; fixed in the commit that added
  this entry). The same defect, and the same Linux semantics, as the macOS one above: a wake takes each waiting fault
  off the queue, read or not (v6.12 fs/userfaultfd.c `userfaultfd_wake_function` :141), where here the event was a
  record left in the userfaultfd's socket, so a fault on a page unregistered before its record was read was served
  with a `UFFDIO_COPY`, `ENOENT`, which Firecracker's handler panics on. Now each Windows userfaultfd has a waiter
  mirror, the twin of the macOS one, and the `userfaultfd` crate returns a page fault only while its waiter waits
  (`test_an_unread_fault_unregistered_is_not_read`, `test_an_unread_fault_filled_with_a_wake_is_not_read`,
  `test_an_unread_fault_woken_is_read_once_as_its_new_fault`, `test_a_blocking_read_waits_past_a_woken_waiters_record`;
  the first three and the last failed before the change; `test_an_unread_fault_filled_without_a_wake_is_still_read`
  passes on both; `test_waits_reads_the_mirror_word` checks the slot read and the `EBADMSG` past the table). What the
  Windows mirror is, as a channel, differing from the macOS twin only in the OS primitives:
  - It is an **unnamed** pagefile-backed section of one page (256 words, one per waiter slot, `MIRROR_WORDS`), which
    the VMM maps read-write and each reader maps read-only. Its direction is VMM to handler only: the VMM never reads
    what a reader could write, and a reader cannot write it. A reader's handle comes from a **distinct**
    reduced-access `DuplicateHandle` that asks for `FILE_MAP_READ` (`SECTION_MAP_READ`) and `SECTION_QUERY` (which the
    reader's check below needs) alone, never `DUPLICATE_SAME_ACCESS` (`dup_mirror_read_only`, `pull_mirror`, not the
    crate's default handle send), and the section's DACL grants Everyone (`WD`) only `SECTION_QUERY |
    SECTION_MAP_READ` and no write, so a reader's handle cannot be re-duplicated up to `SECTION_MAP_WRITE` — the
    access check reads the DACL with the caller's token and finds no write ACE — and its read-only view cannot be made
    writable (`ERROR_ACCESS_DENIED`) (`test_a_mirror_handle_a_reader_gets_maps_read_only`,
    `test_a_read_only_mirror_view_cannot_be_made_writable`,
    `test_a_mirror_handle_a_reader_gets_cannot_be_re_duplicated_to_writable`). The section has no name at any point,
    so no `OpenFileMappingW` can reach it; a reader reaches it only through a read-only handle duplicated out of the
    VMM's (`test_the_mirror_section_has_no_name`). The DACL grants Everyone, not the creator's SID, because a reader's
    token is not known when the section is made (a jailed reader is in another token); it is never narrowed to the
    creator, and it grants read, never write.
  - The transport goes whichever way the two processes' tokens allow, and only that way:

    | VMM | handler | how the handler gets its copy | who opens whom |
    |---|---|---|---|
    | not jailed | not jailed, or jailed | push (`OP_MIRROR`) | the VMM opens the handler (`PROCESS_DUP_HANDLE`) and duplicates the read-only handle into it |
    | jailed | the operator's (not jailed) | pull (`OP_MIRROR_PULL`) | the handler opens the VMM and copies out the VMM's read-only handle |
    | jailed | jailed, apart (an LPAC handler) | none: the read fails, `EACCES` | neither may open the other; not supported, it needs a third process that may open both |

    The push is tried first; a VMM that may not open the handler answers it `-EPERM` (a jail's token opens no
    process outside the jail: `jailer-test.ps1 handoff`), and the handler then pulls: the reply names the VMM's own
    read-only handle of the mirror (made with it, closed at its release), never the read-write one it was made with
    (`test_no_mirror_reply_names_the_read_write_handle`), and the handler takes a copy asking for
    `SECTION_QUERY | SECTION_MAP_READ` alone, not inheritable, without `DUPLICATE_SAME_ACCESS` or
    `DUPLICATE_CLOSE_SOURCE` (`pull_mirror`), out of the process the userfaultfd's socket names as its peer
    (`SIO_AF_UNIX_GETPEERPID`), never a pid of the reply (`test_a_pulled_mirror_comes_from_the_sockets_peer`).
    This is the access the operator already uses to take the userfaultfd itself out of the jail (vmm-sys-util's
    `sock_ctrl_msg`, `FLAG_PULL`); the jailed VMM gains no right, and a handler that may open the VMM for
    `PROCESS_DUP_HANDLE` could take any handle of it already (Learn, "Process Security and Access Rights").
    The push was the only transport from piece 1 (bc9c1f60) to this fix, and a jailed VMM's handler failed its
    first read with `EPERM`: upstream's handler panicked, its panic hook killed Firecracker, and `/snapshot/load`
    got no answer (CI's windows-guest `jailer-test.ps1 uffd`, from 48e2838a; the push had been reviewed for a
    jailed handler only; `test_a_reader_its_userfaultfds_process_cannot_open_pulls_the_mirror` failed before
    the pull, `EPERM`, and serves the fault after it). With neither direction open the read fails with the pull's
    `EACCES`, never reads without the mirror
    (`test_a_reader_and_a_userfaultfd_that_cannot_open_each_other_fail_the_read`).
  - The handler does not trust the VMM: whichever way its copy came, it checks the object before it maps it
    (`check_mirror_section`, `NtQuerySection`): a section (`ENODEV` otherwise), of committed pagefile memory, not a
    file's or an image's and not only reserved (`EOPNOTSUPP` otherwise: a file's page whose read fails would stop or
    end the handler), of exactly the mirror's size (`EPROTO` otherwise), and closes the handle whatever the answer
    (`test_a_mirror_handle_is_checked_before_it_is_mapped`, `test_a_pulled_handle_that_is_no_mirror_fails_the_read`).
    What the VMM writes in the mirror is not trusted either: the view is the table's size, a tag naming a slot past
    it is `EBADMSG` (`test_waits_reads_the_mirror_word`), and a wrong word only makes the reader drop or keep that
    VMM's own faults, which its records could misstate anyway. The reader checks the reply's size before it maps
    (`EPROTO` otherwise, `map_mirror_handle`) and fails the read if the mirror cannot be set up, never reading
    without the check (`test_a_kernel_side_without_the_mirror_fails_the_read`: a serving thread that predates the
    mirror answers `OP_MIRROR` with `-EINVAL`; `test_a_kernel_side_without_the_pull_fails_the_read`: one that
    predates the pull answers `OP_MIRROR_PULL` with `-EINVAL`; a handler that predates the pull is refused
    `-EPERM` by a jailed VMM, as before). A reader that predates the mirror fails on the first page fault, whose
    event type is now `EVENT_PAGEFAULT2` (`test_a_page_fault_record_is_no_type_a_reader_before_the_mirror_decodes`);
    the two backends' `proto` constants are kept in step by a cross-import test
    (`test_the_mirror_proto_matches_the_macos_twin`).
  - The section is not charged to the jail's `memory.max`: a pagefile-backed shared section is not charged to the
    job's commit (the windows-sandbox probe measured 640 MiB of shared section as a 2–6 MiB job peak, fc-win,
    2026-11-10), so the one page a userfaultfd needs no carve-out — 256 mirrors added well under a page of private
    commit each (144 bytes a mirror in a 256-mirror run, the incidental per-context bookkeeping, not the shared
    section, which is the number that varies run to run; a private page each would be 4 KiB, 1 MiB over the 256),
    not a page (`test_the_mirror_is_not_charged_as_private_commit`). The mirror's cost on the fault path
    is below the measurement's resolution: a fault round-trip is about 28 µs a page with the mirror and the same with
    a single extra user-mode PID read, against 77 µs with 30000 of them a serve (the control that shows the
    measurement resolves a per-serve cost), so the mirror's handful of uncontended atomics do not show
    (`test_the_mirror_cost_on_record`, MIRRORCOST).
  - One mirror a userfaultfd (at most 16, `MAX_CTX`), given back at its release on both sides: the VMM unmaps the view
    and closes the section and its own read-only handle (the pull's) once no thread uses it (an enter/leave count the
    release drains before it frees, `destroy`), and a reader unmaps its view when it is dropped. A pull's value read
    after that release names no mirror, or, the value reused, another handle of that VMM: the check above refuses all
    but a section of the mirror's size and backing, and another userfaultfd's mirror of the same VMM would only
    misstate that VMM's own faults. The drain closes the same write-after-close race the macOS side had: a waiter's
    write of its record, or an `OP_MIRROR` or `OP_MIRROR_PULL` in flight, cannot reach a section the release freed
    meanwhile. The Windows sandbox blocks child-process creation and does not name objects (it is not Seatbelt), so
    the unnamed section needs no path rule.
- **macOS: a memfd and a waiter mirror had a name anyone could guess while they were made** (the memfd from
  9fc77c46, the compatibility memfd's start; the mirror from bdf94c63; under "Not at parity yet" in a554ef2c; fixed in
  the commit that moved it here). On Linux a memfd has no name: its file is made unlinked (v6.12 mm/memfd.c :393,
  `shmem_file_setup`). Here each is a POSIX shared memory object, which has a name from its `shm_open` to its
  `shm_unlink`: the compatibility memfd's (guest memory when Firecracker backs it with a memfd) for no call between,
  a userfaultfd's waiter mirror across one, the read-only open whose descriptor readers get. The names were the pid
  and a counter (`/fcm.<pid>.<n>`, `/fcmH.<pid>.<n>`, `/fcm.<pid>.u<n>`) and the mode `0600`, so:
  - a process of the VMM's uid not under a jail's profile (whose `shm_rule` allows only its own pid's names, another
    ending it: `test_own_memfds_are_made_after_narrow`), and root, could open the name meanwhile for reading and
    writing: an open of an existing object asks `pshm_access`, the owner's bits for any uid but root's
    (xnu-12377.121.6 bsd/kern/posix_shm.c :534, :781 to :791), and the mode is kept whole, with no umask (:422). On
    Linux such a process reaches a memfd at any time through `/proc/<pid>/fd/<n>`, with ptrace read access (v6.12
    fs/proc/base.c `proc_fd_access_allowed` :709 to :722, used at :1806 and :1849: the same uid and a dumpable VMM,
    kernel/ptrace.c :317 to :322, :341 to :344, which Yama does not restrict, security/yama/yama_lsm.c :362, and
    upstream never makes itself non-dumpable); on macOS one that is not root gets no other's task port without the
    MAC policy's check and taskgated's authorization (bsd/kern/kern_proc.c `task_for_pid` :5941, :5948 to :5969), so
    the window was a reach into guest memory it had no other way to;
  - a process of any uid could take a name first: the names are one namespace for every uid (`pshm_cache_search`,
    :223, by name alone) and `O_EXCL` fails on an existing one, whoever's it is (:492 to :495), so a memfd's
    creation failed with `EEXIST` and the VMM did not start; a mirror went on to the next number.

  Now a memfd's object is made with mode `0` and a mirror's with `0400`, each named with its prefix, the pid and 64
  random bits from `getentropy` (16 hex digits, at most 28 bytes of the 31 macOS allows), still under the profile's
  prefixes, so `shm_rule` and the profile are unchanged; `getentropy` is in both profiles' lists. A failed
  `getentropy` fails the creation, with no predictable name in its place, and a name drawn and found taken is
  drawn again, 8 times at most, then the creation fails. The maker's descriptor, opened by the call that made the
  object, reads, writes and maps it whatever the mode. While the name is there, a second open of it by the same uid
  is `EACCES` for a memfd, for reading and writing and for reading, and `EACCES` for reading and writing a mirror,
  which opens for reading (`test_a_memfd_opens_for_no_one_else_while_it_has_its_name`, plain and huge page;
  `test_a_mirror_opens_for_reading_only_while_it_has_its_name`; with the mode `0600` again each fails, the second
  open reading and writing). With the counter's names taken first, a memfd is made, plain and huge page
  (`test_a_memfds_name_cannot_be_taken_first`; with the counter's names it fails, `EEXIST`), and two mirrors are
  made with names of 16 random hex digits that differ (`test_a_mirrors_name_cannot_be_guessed`; with the counter's
  names it fails on `/fcm.<pid>.u256`, the counter having skipped the 256 taken, so what it shows is that no name
  is guessable, the creation having gone on before too). Taken here by the same uid, which `O_EXCL` refuses as it
  refuses any; that another uid's object is refused alike is from the source above, not run. What stays:
  - root opens either while it has its name, as root on Linux opens any process's descriptors;
  - a process of the VMM's uid not under a jail's profile can read the name from the VMM's descriptor
    (`proc_pidfdinfo`, which xnu allows the same uid: bsd/kern/proc_info.c :2900, `proc_security_policy` :3193; the
    name is kept after the unlink), and so could open a mirror for reading while it has its name, across the
    read-only open: that gives waiter tags, slot numbers and counts, no guest data. With one uid per jail, the
    processes of a jail's uid are that jail's own.
- **macOS: a reader of a userfaultfd range without the lock could read one range's bounds with another's arrays, and
  every registration leaked its arrays** (from 6c4320c5, the macOS userfaultfd's start, to the commit that brought
  `Range::gen`; found by reading, not observed). The signal handler, `fault` and the stage-2 side read a slot's
  start, end, page size and per-page arrays without `LOCK`. A slot released and taken by another range between those
  loads gave the old bounds with the new arrays: an index past the end of a smaller array, an out-of-bounds read in
  a signal handler, or a page of the other range read as missing, its fault posted to a userfaultfd that never
  registered the address. It needs a release and a register, under `LOCK` on another thread, to land between one
  reader's few loads. Now each slot has a sequence count, odd while a writer changes its fields (stores only: no
  allocation, lock or system call in the window); a reader reads it before and after and starts over on a change
  (`test_a_reader_between_its_generation_reads_starts_over`), `fault` validates it once its waiter is registered,
  read after the page's bits (`test_fault_validates_after_its_waiter_is_registered`,
  `test_fault_reads_the_generation_after_the_page`), a fault inside a writer's own window goes to the previous
  handler instead of waiting on itself (`test_a_fault_inside_a_writers_window_goes_to_the_previous_handler`), and
  every index is checked against the capacity the array holds (`test_an_index_past_an_arrays_capacity_reads_nothing`).
  The arrays (a byte for the owner, a byte for the asked protection and a bit for missing a page, which were leaked
  at every new range) belong to their slot and only grow, with the peak of what is registered at once, not with how
  often: a slot holds less than twice its largest arrays, which have room for the next power of two of its largest
  range's pages (64 at least), so less than four times what that range needs past that floor (136 KiB for 1 GiB of 16 KiB pages, a power of two:
  under 272 KiB with any arrays it outgrew) (`test_register_and_release_in_a_loop_keeps_the_array_count_flat`).
- **Windows: a reader of a userfaultfd range without the lock could read one range's bounds with another's arrays,
  and every registration leaked its arrays** (from b0dfb35b, the Windows userfaultfd's start, to the commit that
  brought `Range::gen` there; found by reading, not observed; the macOS entry above). The process's exception
  handler (`resolve_access`: `is_missing`, `fault`), the WHP run loop's `fault` at a guest's access to a missing page,
  and the system calls' prefault read a slot's start, end and per-page arrays without `LOCK`. A slot freed (its
  memory unmapped or mapped over) and taken by another range between those loads gave the old bounds with the new
  arrays: an index past the end of a smaller array, an out-of-bounds read inside the exception handler, or a page of
  the other range read as missing, its fault posted to a userfaultfd that never registered the address, the access
  waiting for a fill that would not come. It needs an unmapping and a register, under `LOCK` on another thread, to
  land between one reader's few loads; Firecracker registers its guest memory once and unmaps it at its exit, as
  read from the code. Now each slot has a sequence count, odd while a writer changes its bounds (stores only: no
  allocation, lock or system call in the window, so no exception can be raised inside it, and a lookup that finds
  its own thread's window open ends the process with a line,
  `test_a_lookup_inside_its_own_writers_window_ends_the_process`); a reader reads it before and after and starts
  over on a change (`test_a_reader_between_its_generation_reads_starts_over`), `fault` validates it once its waiter
  is registered, read after the page's bits (`test_fault_validates_after_its_waiter_is_registered`,
  `test_fault_reads_the_generation_after_the_page`), and every index is checked against the capacity the array
  holds (`test_an_index_past_an_arrays_capacity_reads_nothing`). The arrays (a byte for the owner and three bits a
  page: missing, no read, no write) belong to their slot and only grow, with the peak of what is registered at
  once, not with how often (`test_register_and_unmap_in_a_loop_keeps_the_array_count_flat`): 352 KiB for 1 GiB of
  4 KiB pages, a power of two, under 704 KiB with any arrays its slot outgrew. Windows Server 2022 20348 and 2025
  26100; each test ran on the code with its check taken out and failed there (the commit names each).
- **Windows: a register whose close of a missing page failed returned the error with its range registered** (from
  b0dfb35b, the Windows userfaultfd's start; found by reading, not observed). A range not on a reserved section
  (since those came, only in a process whose exception handler could not be added) is published, then its missing
  pages are closed (`PAGE_NOACCESS`); a close that `VirtualProtect` refused returned its error with the range
  registered, the runs before it closed and the rest open while missing, read as zeros with no fault. Now the range
  is unregistered whole, as an unregister leaves it: its missing pages opened with the protection `mprotect` gave
  them, every page no userfaultfd's, the waiters woken, and its slot kept, so the memory registers again; a freed
  slot would leave the memory the section's view, which a register refuses with `EINVAL`
  (`test_a_register_whose_close_fails_leaves_the_range_in_no_registration`, through a hook that fails the second
  close; 15 of its checks failed on the code before, and the register again failed with the slot freed). A reopening
  that fails too ends the process with a line (`test_a_register_whose_reopening_fails_ends_the_process`). Linux's
  register changes no page's protection and has no such failure. Windows Server 2022 20348 and 2025 26100.
- **Windows: a heap allocation the memory limit refused ended the VMM with 0xC0000409, with no reclaim** (from the
  Windows port's start; found by reading, review of the MOVEUNDERVCPU test, not observed in a VMM). Rust's allocation
  error calls `std::process::abort` (`__fastfail`), where Linux's memory cgroup reclaims and then kills the VMM with
  SIGKILL at the page it cannot charge (v6.1 mm/memcontrol.c `try_charge_memcg` :2681, :2705 to :2706, :2729;
  mm/memory.c `do_anonymous_page` :4117 charges a heap page at its first touch). Now every Windows binary that
  links the VMM has wick's allocator (`libc::wick_alloc`, `vmm::ext::allocator`), which answers a refusal by the
  size asked, as Linux answers malloc (mm/util.c `__vm_enough_memory` :1002 to :1006 refuses only above RAM and
  swap; mm/mmap.c :2552 to :2554 asks no memory cgroup): above the host's commit limit, null, as the system's
  allocator (`test_a_heap_allocation_above_the_hosts_commit_limit_is_refused_as_the_systems`); above what the
  job's limit holds in all, 137 and a line saying so, where Linux gives it and kills at the touch past the limit,
  so a reservation never touched, which lives on Linux, ends here
  (`test_a_heap_allocation_more_than_the_job_limit_holds_ends_with_137_and_says_so`); else the reclaim runs
  once and the allocation is asked again if it gave something back, else the VMM ends with 137 and a line naming
  the size and what the reclaim gave back; no reclaim runs with a lock of wick's memory layer held, in the
  exception handler or on the reclaim's own thread, where the VMM ends at once
  (`test_a_heap_allocation_refused_at_the_limit_ends_with_137_and_a_line` for an allocation, a zeroed one and a
  reallocation, `test_a_heap_allocation_refused_at_the_limit_is_made_after_the_reclaim`,
  `test_a_heap_allocation_refused_where_no_reclaim_may_run_ends_with_137`; each failed with 0xC0000409 on the code
  without the wrapper, and the last made its allocations after a reclaim with its check taken out). wick's own
  `try_reserve` sites (a register's record bitmaps, the reclaim's lists and discard guards) answer `ENOMEM` as
  before (`test_a_guarded_fallible_site_answers_enomem_at_the_limit`, which ended with 137 with the guard taken
  out). Upstream's and std's fallible growth (`fs::read_to_string` of the config file, the metadata file and a CPU
  template; `read_to_end` of a snapshot's state and of the seccomp filters) answers its error above the host's
  RAM and pagefile, as on Linux, and ends the VMM with 137 for a growth the limit cannot hold in all or one that
  fits the limit but not what is left of it, where it returned an out-of-memory error, as Linux's memory cgroup
  kills at the touch. Firecracker names its heap's allocator in a debug line at a VM's build (`boot-test.ps1
  boot`; `test_the_heaps_allocator_is_wicks`). Windows Server 2022 20348 and 2025 26100.
- **Windows: a register that could not give a page holding memory its protection returned with the page more open
  than `mprotect` made it** (from b0dfb35b, the Windows userfaultfd's start; found by reading, review of the fix
  above, not observed). The section's view is mapped read-write and each run of pages that holds memory gets its
  protection back before the range is published; a refusal (`VirtualProtect` on the process's own committed view,
  which a guest does not reach: the VMM registers its memory at a restore, from its own code) gave the range back and
  returned the error, leaving that run and the ones after it read-write where `mprotect` made them read-only or
  inaccessible, and the memory one a later register refused with `EINVAL`; on a reserved section a missing page's
  next access ended the process with an unhandled 0xC0000005 (the code before, 20348 and 26100). Now the process ends at the
  refusal with a line naming the run, the protection it should have, the one it has and the error
  (`test_a_register_that_cannot_protect_a_resident_page_ends_the_process`, through a hook that fails the run's
  protection, both kinds of section; on the code before it returned the error with pages 2 and 3 at
  `PAGE_READWRITE` for `PROT_READ`). Linux's register changes no page's protection and cannot fail so. Mapping the
  view closed and opening each run after the copy would leave a refused run narrower, but it would put a
  `VirtualProtect` on every run, read-write ones too, end the process later at an access with no line when one is
  refused, and keep the resident pages closed and unregistered until the last opening, so it is not taken (the
  register's doc). Windows Server 2022 20348 and 2025 26100.
- **Windows: a guest access to guest RAM that the host refuses ended the VMM with an access violation, and a store to
  a read-only memory slot waited a million runs again or for ever** (found by reading, review of the WHP run loop's
  memory access exit; failing first in the decision's own shape: `test_a_ram_access_is_decided_in_kvms_order`, 11
  of its 15 rows against the old order written in that shape, the module run alone on macOS). KVM gives a write to
  a `KVM_MEM_READONLY` slot to the VMM as MMIO before it looks at the page (v6.1 virt/kvm/kvm_main.c `__gfn_to_hva_many` :2405 to :2406, `__gfn_to_pfn_memslot` :2705 to
  :2709; arch/x86/kvm/mmu/mmu.c `kvm_handle_bad_page` :3159 to :3160), and fails `KVM_RUN` with `EFAULT` for a host
  page it cannot fault in (`hva_to_pfn` :2679 to :2690, `kvm_handle_bad_page` :3167). The WHP run loop asked the
  commit and, with a userfaultfd registered, `wick_uffd::fault`, then ran the access again up to a million times
  (60ae1f52) before emulating it, and without a userfaultfd emulated it at once; the emulation copies a RAM operand
  through the host (c56eb138; before it the access read zeros). So, as read from the code:
  - a store to a read-only slot with a userfaultfd registered (Firecracker's read-only pmem after a restore from
    one) ran again a million times and logged "guest RAM ... stays inaccessible", which was false, before its MMIO
    exit; over lazy writable memory (`MAP_NORESERVE` under a read-only slot) it ran again without end, the commit
    answering each time;
  - a guest access to a page whose host protection refuses it (or under which nothing is mapped) was emulated, and
    the host's copy ended the VMM with 0xC0000005, where KVM fails the run with `EFAULT` and Firecracker's vCPU
    ends the VMM with its error.
  Now the exit is decided in KVM's order (`exit::ram_access`): a write to a read-only slot is MMIO at once; then the
  commit and the userfaultfd; then one look at the page under the locks every change of it takes
  (`wick_mm::settled_access`: the userfaultfd's lock, the region table's, the released records', the lazy ranges'),
  so that a fill, discard, move or release between the looks is seen whole: a page they would resolve is asked of
  them again, one the host allows runs again, one it refuses fails the run with `EFAULT` and a line naming the
  address and the access (`test_a_page_changed_between_a_vcpus_looks_is_settled_as_it_is_now`, Windows Server 2022
  20348 and 2025 26100). A page the host allows that keeps exiting fails the run so once its runs again in a row
  have lasted a second and number at least 64, said as such, with the count and the time (`exit::RamRetries`,
  `test_runs_again_fail_the_run_after_a_second_and_64`; before, after a million, which took 48501 ms for a write and
  23271 ms for a lazy read, the vCPU spinning; on WHP the time is asserted from 1 s to under 10 s by
  `test_a_guest_ram_access_exit_is_decided_as_kvms` (its first WHP run: a write kept exiting ran
  again 19987 times in 1000 ms, a lazy read 43230, each failing the run well inside 10 s). The most runs again in a row of
  one access is said in a RAMRETRY line at each new power of two, which `boot-test.ps1 boot` prints. Until the follow-up (found by reading, review of this fix), a page the commit found there
  already, lazy memory committed before or a released page resolved before, started the count again at each exit,
  the commit answering committed, and ran again without end; the commit now answers it present and it is counted
  (`test_a_lazy_page_committed_before_is_present_when_asked_again`,
  `test_a_released_page_resolved_before_is_present_to_the_commit`, Windows Server 2022 20348 and 2025 26100).
  `test_a_guest_ram_access_exit_is_decided_as_kvms` asserts each case and the runs again it took on WHP, the
  committed lazy page among them (not run here; its first run was CI's, the figures above). What stays: an emulated instruction's other operand in RAM is
  still copied by the host on the vCPU thread, and a page the host refuses there ends the VMM with 0xC0000005
  (docs/COMPATIBILITY.md, `mem_size_mib`).
- **Windows: a guest's write of `IA32_TSC` or `IA32_TSC_ADJUST` could end its own VMM while another of its vCPUs was
  in a TSC-deadline exit** (from 87d03287, which suspends partition time for such a write, `guest_tsc_write`, in
  every WHP guest; found by CI's `jailer-test.ps1 x2storm`, twice, both times in the fourth pair's storm, about
  5.5 s in; why that pair was not found). WHP refuses the legacy local
  APIC get and set (`WHvGetVirtualProcessorInterruptControllerState` and its set) with WHV_E_INVALID_VP_STATE
  (0x80370308) when they overlap another thread's `WHvSuspendPartitionTime` call, and no other state call, nor
  either of them while time is suspended or being resumed (TIMEGET, `test_state_calls_against_time_suspension_on_record`,
  its first CI run: in the transitions arm 5387 of 9195 legacy gets refused on a VP that had run and 5955 of 9396
  on a VP not run, each in a phase that overlapped the Suspend call; State2 get and set and `WHvRequestInterrupt`
  never, so no interrupt request is lost to it). The backend's hold (`with_time_stopped`) keeps
  the other vCPUs out of the guest, not out of their exit handlers, so a vCPU's own `IA32_TSC_DEADLINE` exit made the
  legacy get during the hold's Suspend call, and the refusal failed its run (exit 1, "os error 87"). The trigger is
  any guest's TSC or TSC_ADJUST write (Linux writes TSC_ADJUST on a secondary CPU whose value differs, v6.1
  arch/x86/kernel/tsc_sync.c 231 to 233), and in record builds the held LVT timer write; it ends only the guest's own
  VM, and KVM never fails there. Now each Suspend call holds a per-partition gate exclusive and each legacy exchange
  holds it shared for its call alone (`VmInner::state_gate`), so the two never overlap: a legacy exchange waits at
  most for one Suspend call (16 to 218 us unloaded in that run, up to 32 ms with every processor busy), the Suspend
  for the exchanges under way. The legacy exchanges through the backend's own path while another thread holds the
  VM in a loop are none refused (`test_legacy_apic_exchanges_wait_for_a_suspension_of_time`, its first WHP run: with
  the gate, 762 holds of time suspended and 29088 legacy gets and 29088 sets made meanwhile, 0 refused; on the commit
  before the gate the same test did 31019 holds and had 90282 refused, as it must fail first; the holds are fewer with
  the gate because a hold now waits for the exchanges under way, about 2 ms a hold under a continuous reader), and a
  refused exchange's line now names its caller's line and where partition time was
  (`test_a_refused_legacy_get_names_its_caller_and_the_suspension`, its first WHP run: the line names its caller,
  `vcpu.rs:13513`). The documented call
  (`WHvGetVirtualProcessorState` of `InterruptControllerState2`, never refused in TIMEGET) is the later step.

## Not at parity yet

Until these are done, **do not run untrusted multi-tenant workloads on macOS or Windows hosts.** On Linux, wick is
upstream Firecracker and its jailer.

- **Windows: the page tables of a userfaultfd fill are charged to the VMM's job, where Linux charges them to the
  filling process's cgroup.** Measured on Linux 7.0.0-1017-gcp (Ubuntu 24.04, cgroup v2, the VMM's cgroup at memory.max 64M and
  memory.swap.max 0, a 64 GiB registered mapping filled by a handler process with `UFFDIO_COPY`, three runs of each
  case, the same each time): the copy the VMM's cgroup cannot charge sets off the cgroup's OOM killer, which kills
  the VMM with SIGKILL (`memory.events` `oom_kill` 1); with the handler in the VMM's cgroup it then kills the handler
  too (`oom_kill` 2), and with the handler in another cgroup the handler's next copy, the VMM gone, returns -1 with
  `ENOMEM`. While the VMM lives, no copy is refused. This is what v6.1's charge path does: it reclaims, then calls
  the OOM killer and charges again once a task was killed, and returns `-ENOMEM` only when no task can be killed
  (mm/memcontrol.c, `try_charge_memcg` :2714 to :2743, `mem_cgroup_oom` :1891). Here, the same now: a fill the job
  still refuses after the reclaim at the limit (`reclaim_for_a_fill`, which lists the chunks it passed over for system
  calls copying them; the fill waits for those calls, moves the chunks and reclaims again, the memory.max row) ends the VMM with 137 and a line naming the fill, the
  bytes it filled and the chunks it waited for, so the handler finds its socket closed
  (`test_a_fill_past_the_job_limit_ends_the_vmm_with_137`, `test_a_fill_with_nothing_reclaimable_ends_named`; before,
  the handler got `ENOMEM` and the VMM went on). What stays different: the page table a fill needs is charged on Linux
  to the filling process's cgroup, not the VMM's (with the handler in another cgroup the VMM was killed at anon-rss
  65628 kB and pgtables 65708 kB under the 64 MiB limit; with it in the VMM's, at 32816 kB and 32840 kB), where here
  every page table of the VMM's memory is the VMM's own commit, in its job, so the VMM reaches its limit sooner by
  those tables. Firecracker's handler is a process of the operator's, which the jailer does not put in the VMM's
  cgroup.
- **Windows: the first or last 2 MiB chunk of a userfaultfd range not on 2 MiB boundaries is never moved by the
  reclaim nor given a new section when it is discarded whole, so its dead pages are not reclaimed and its
  whole-chunk discard keeps its commit (its pages missing, or pending in a released range, all the same).** The reclaim's move and the swap of a chunk discarded whole put a
  new section in the place of a 2 MiB chunk's old one in the alias and then the guest's range, where the chunk is
  mapped as two views split at its midpoint. A view's unmap gives back the page table of each 2 MiB region only that
  view maps, and a page-directory page for each 1 GiB only it maps; its map takes them again (VIEWCOST,
  `test_what_a_chunks_view_swap_costs_on_record`). The views are swapped one at a time, each unmapped keeping its
  placeholder and the new section's mapped there before the next, so the chunk's other view, of the old section or
  the new, keeps the region's table: every step takes and gives back 0 KiB for a range on a 2 MiB boundary, as
  Firecracker places every guest memory region (src/vmm/src/vstate/memory.rs, `GUEST_MEMORY_ALIGNMENT` :42,
  `allocate_protected` :131 to :200), for any chunk of a range placed anywhere, and for a range 64 KiB past a boundary
  but its last chunk's second view, alone in its region (-4 and +4 KiB at b176e726; that chunk is not swapped since
  review B3, below) (VIEWCOST, on Windows Server 2022 20348 and 2025 26100). The move's own view of its new section is mapped into a slot made at
  the first registration, beside two anchors that keep its regions' tables, so its map and unmap take and give 0 KiB
  (`test_a_moves_temporary_view_takes_no_commit`: +2068 KiB once for the move budget and the slot, then 0 at each
  move, a short last chunk's too). With no room left in the job and another commit taking all it can between a
  view's unmap and its map, a move is made with the guest view's room taken and with the alias's, and a discard's
  swap with the guest view's (`test_a_move_whose_guest_view_room_is_taken_is_made`,
  `test_a_move_whose_alias_room_is_taken_is_made`, `test_a_discard_whose_guest_view_room_is_taken_is_made`, on
  20348 and 26100; with a chunk's two views swapped together, at 9dcf90d0, the map was refused and the VMM ended with 137 and
  the line "wick: guest memory: committing the pages at ... failed with error 1455"). What stays: a view alone in
  a 2 MiB region of its range, at the edge of a range that starts 1 MiB or more past a 2 MiB boundary or ends within
  its last chunk's last view past one (a short last chunk of one view, under 128 KiB, too); its unmap would give back
  the table, and a commit of another thread could take it before the map, which wick's own commits wait for (it
  holds the region table's lock) and the Rust heap, a thread's stack and Windows' own allocations on other threads do
  not. Such a chunk is refused before any step (`windows_mm::at_a_ranges_edge`), with a counted line on standard
  error: the reclaim moves another chunk, and its whole discard drops its pages in place, as a partial discard does,
  keeping their commit and charge until the chunk is unmapped
  (`test_a_chunk_at_a_ranges_edge_is_neither_moved_nor_swapped`, on Windows Server 2022 20348 and 2025 26100; before
  review B3 it was swapped, and ended the VMM with 137 if another commit took the room). The job and the jail's count
  then read that chunk's dead pages more than Linux's memory.current, within `memory.max`: a stated difference from
  Linux, whose reclaim frees pages in place, for such ranges only. Firecracker's guest memory is never one (it starts
  on a 2 MiB boundary and is whole MiB), and wick's mmap places an anonymous private mapping of a multiple of 2 MiB on
  a 2 MiB boundary (`test_a_whole_2_mib_anonymous_mapping_is_placed_on_a_2_mib_boundary`), so such a range is one of
  another length, or one placed by a hint or `MAP_FIXED` (making such a chunk movable is review B4's, owed).
- **Without the jailer, the VMM runs as the user who started it** on macOS and Windows: an escape from the VM and
  then the VMM lands as that user (files are then not limited, as on Linux without the jailer).
- **macOS: a page is charged to the memory limit once for each mapping that touched it.** The jail's memory limit
  (`memory.max`, `memory.limit_in_bytes`) is a jetsam limit: the jailer spawns Firecracker with it, fatal when active
  and when inactive, in whole MiB (overlay/jailer/platform/macos/mod.rs `posix_spawnattr_setjetsam_ext` :934 to
  :939), and with the API process on, Firecracker sets its own to the limit less 32 MiB, which the API process takes
  (overlay/vmm/ext/jail.rs :659 to :662, :540, `limit_memory` :475). A jetsam limit is a limit on the process's
  phys_footprint ledger, and the process is killed with SIGKILL past it (xnu-12377.121.6 bsd/kern/kern_memorystatus.c
  :261, osfmk/kern/task.c `task_set_phys_footprint_limit_internal` :7602, the ledger's limit :7649). Measured on an
  M1 Pro, macOS 27.2, 64 MiB at a time, three rounds each the same: phys_footprint counts a page once for each
  mapping that has touched it. Plain guest memory the guest wrote (Hypervisor.framework's stage 2) and the VMM then
  read is charged 128 MiB, anonymous or a shared memory object as the compatibility memfd makes
  (`test_anonymous_guest_memory_is_charged_once`, `test_shared_guest_memory_is_charged_once`), and so is plain memory
  a userfaultfd filled that the guest and then the VMM read (`test_a_guest_read_of_filled_pages_is_charged_once`).
  Firecracker's anonymous guest RAM is not plain memory since the owned-memory fix (next entry): the boot's memory
  and a userfaultfd restore's (vstate/memory.rs `owned_guest_commit`: `fd == -1`, no huge pages) are purgeable
  objects the task owns, charged by the object whatever maps them, so the same steps are charged once, 64 MiB, in
  the same run as the plain ones' 128 (`test_owned_anonymous_guest_memory_is_charged_once`: the guest's write +64,
  the VMM's read +0; `test_owned_guest_read_of_filled_pages_is_charged_once`: the fills +64, the guest's and the
  VMM's reads +0, so a filled page is charged at the fill, as on Linux). Still charged once for each mapping is the
  guest memory that is not owned: a `File` snapshot restore's (`MAP_PRIVATE` of the memory file), a vhost-user
  backend's (the compatibility memfd) and a huge-page guest's. On plain memory a
  userfaultfd fill writes through a mapping of the pages made for it and taken away once it is done
  (`libc::wick_uffd::fill_view`), so the fill itself is charged nothing and the pages are charged by the mappings
  that touch them after: 64 MiB filled and read by the guest alone is charged 64 MiB
  (`test_filled_pages_only_the_guest_reads_are_charged_once`), and filled and read by the process 64 MiB
  (`test_a_filled_page_is_charged_once`); before, the fill wrote through `wick_uffd`'s alias, a second mapping of every
  registered range kept while it was registered, and these were 128 and 128 MiB, and 192 MiB read by the guest and
  the VMM; CI's macOS runner charged the same way (CI's macos job at 6a7a8237: `test_a_filled_page_is_charged_once`
  failed there as listed, "compat-libc: 102 pass, 1 fail as listed"), so the charge per mapping is macOS's, not one
  Mac's. A guest's write alone is charged once (`test_madvise_dontneed_replaces_guest_pages` bounds it). Linux
  charges a page to the memory cgroup once, when it is allocated (v6.12 mm/memory.c `alloc_anon_folio` :4711,
  mm/shmem.c :1818; mm/memcontrol.c `commit_charge` :2370 refuses a second charge), and a `UFFDIO_COPY` page at the
  fill (mm/userfaultfd.c `mfill_atomic_pte_copy` :302), whatever then maps it, KVM's stage 2 included. So a jailed
  VMM whose guest memory is not owned (a `File` restore, a vhost-user backend, huge pages) is killed by jetsam when
  the pages both its guest and it have touched (a device's queues and buffers; every page, when it writes a
  snapshot's memory) reach half of what Linux would let them be. The three tests that make a VM and ask for one
  charge where two mappings touched plain pages fail and are listed as no-hvf, as the record of that
  (tools/macos/unit-test-differences.txt; CI's runners make no VM, this Mac is where they run). The other way, on
  plain memory (a huge-page guest restored through a userfaultfd), a page a userfaultfd filled and nothing has
  touched yet is held and charged to no one until something touches it, where Linux charged it at the fill. For a VMM that works as it should, that is at most the registered memory the
  handler filled ahead of the guest's accesses (a fill in answer to a fault is followed by the access that
  faulted); a compromised VMM can hold any amount that way (next entry). The kill at the limit: under the jailer's
  memory.max of 96 MiB, a process that fills 64 MiB through a userfaultfd and reads it lives, and the same with a
  second mapping of the pages read too, as the alias was, is killed at the read (`jailer-test uffd-charge`, no VM,
  root, in CI's macos job; not run on this Mac, where root is not used). The owned-memory fix charges the boot's
  and a userfaultfd restore's guest RAM once (above); for a `File` restore, a vhost-user backend's memfd and a
  huge-page guest it is not done, so for those give a jail's `memory.max` room for twice the guest memory the VMM
  will touch.
- **macOS: the jail's memory limit bounds a compromised VMM's guest memory, not its own.** The limit is a jetsam
  limit on the process's phys_footprint (entry above), and a process can keep memory resident that this ledger does
  not count: anonymous memory written only through a second mapping of it that is then removed (the calls a
  userfaultfd fill makes, which the run-phase profile allows for that), or made reusable (`MADV_FREE_REUSABLE`) and
  written again. No counter per process that was found serves as a bound either. So a compromised jailed VMM could
  hold memory past `memory.max`, bounded by the host's memory and swap, not by the jail. Linux's memory cgroup
  charges every page when it is allocated, so a VMM in a cgroup cannot. The accounting is xnu's known, public
  behaviour, not a new vulnerability; wick's part is what it means for the jail.
  Guest memory is now bounded: it is committed as objects the task owns — purgeable, nonvolatile 2 MiB chunks
  (`mach_vm_allocate` with `VM_FLAGS_PURGABLE`), charged by the object to `purgeable_nonvolatile`, part of the
  footprint, whatever maps or writes their pages (the Hypervisor.framework's stage 2 and a userfaultfd fill's
  mapping included), so a write through a removed mapping is counted. A balloon or userfaultfd discard gives a whole
  chunk's charge back, or zeroes a partial chunk with `madvise(MADV_ZERO)` and pins it; once a chunk is half dead a
  reclaim, under the quiesce the guest-slot replace hook gives, replaces its object with one holding only the pages
  that are currently non-zero (the drop decided by content, not by the discard history; a page a userfaultfd has not
  filled is never read, and stays missing, `test_a_reclaim_reads_no_missing_page`), so the pinned charge falls to the live set (`crates/compat/libc/src/wick_owned.rs`; `test_owned_*` under Hypervisor.framework, and
  `test_owned_memory_path_survives_each_profile` under both sandbox profiles). Under memory.max of 96 MiB, the first
  way on a purgeable object is killed, and a userfaultfd that fills 128 MiB on a purgeable object is killed during
  the fills, where the plain fills live (`jailer-test uffd-charge`, whose `uffd-charge-purgeable` case must be
  killed and whose `uffd-charge` case must live; root, CI's macos job, not run on this Mac). Still here, under "Not at parity yet": the VMM's own memory (its heap, buffers)
  is not bounded this way, and guest memory made by a `File` snapshot restore (`MAP_PRIVATE` of the memory file) or
  shared with a vhost-user backend (the compatibility memfd) cannot be a purgeable object as it is, nor is a
  huge-page guest's committed as one; macOS's
  memory-pressure jetsam of the whole host still applies to both. The mechanics, the measurements and the probe for
  each, what was looked at for a bound per process, and the public sources:
  [docs/macos-memory-limit.md](docs/macos-memory-limit.md).
- **macOS jailer: no namespaces in the kernel.** macOS has no network or PID namespaces (XNU's system calls,
  bsd/kern/syscalls.master, have no `unshare`, `setns` or `clone`): IP networking is denied by the sandbox; a
  jailed VMM uses Unix socket endpoints in the jail or in the directory `--netns` names, the jail's network.
  vmnet is the host's network, so it is refused with `--netns`. Without `--netns`, vmnet's bridged mode, and every
  mode before macOS 26, needs root, which a jailed VMM does not have; shared and host mode on macOS 26 need only
  the virtualization entitlement (`vmnet_network_create`): a jailed Firecracker starts both (`jailer-test vmnet`, as
  root in CI's macos job on macOS 26.7.2, e7de455, no guest); a jailed guest on vmnet (`jailer-test vmnet-guest`)
  is written, not yet run. A vmnet interface is started only while the microVM is built: its start
  talks to NetworkSharing (a root daemon) over XPC, which the narrowed sandbox does not allow, so one hot-plugged
  into a running microVM is refused with an API error (`test_vmnet_hotplug_after_narrow_is_refused`). Firecracker starts as root and enters the jail before anything else
  runs (dyld cannot start a program inside a chroot), from a root-owned copy of the binary outside the jail.
- **macOS: a running microVM may remove the sockets in its directory of endpoints.** Upstream's filters have no
  `unlink`: a TAP has no name, and closing it frees the interface's name (drivers/net/tun.c, v6.1,
  `tun_chr_close`). Here an endpoint is a socket file, so a net device that goes (unplugged, or hot-plugged and then
  refused by the API after its endpoint opened) removes the file it bound, by its inode, and the name can be
  hot-plugged again (`test_a_hotplugged_endpoint_frees_its_name_when_it_goes`, `test_a_dropped_endpoint_frees_its_name`).
  The narrowed sandbox allows that one operation: `file-write-unlink` of sockets (`vnode-type SOCKET`, required
  together with the directory in one `require-all`) under the directory of endpoints named without a path: the jail's
  own directory of its network, the network given without the jailer (`WICK_NETNS`), or outside a jail and a network the
  user's `firecracker-net`. Nothing else there (not
  a regular file, not the directory itself) and no socket elsewhere (`test_unfiltered_syscalls_are_limited_by_their_rule`,
  on macOS 15 and 26 in CI's macos-seatbelt job and on 27). What it opens to a compromised VMM: in a jail, the removal
  of its own endpoints only, as its directory there is its own; outside a jail, of other microVMs' endpoints of the
  same user, which that user's unjailed VMM can already reach (it runs as the user). A jail without a network gets no
  such rule, and an endpoint at a path stays when its device goes.
  A Firecracker that may make an interface (root) may also remove the `.lock` files directly in the network directory
  that their owner may write, the sandbox's outer bound, so that a lock file it made goes with its device; it removes
  only one its own open made (`O_CREAT|O_EXCL`), the one its lock is on, by its identity, never one that was there,
  whatever its mode (`test_the_creator_makes_a_name_nobody_made`, `test_a_creator_leaves_an_operators_lock_file`,
  `test_a_jail_reaches_only_lock_files_in_its_network`). A lock file a creator made can stay after it, nobody's, two
  ways: the creator was killed, as its endpoints stay
  (`test_a_killed_creators_lock_file_stays_and_is_nobodys`), or, in an ordinary run, another creator's open locked
  the new file first: xnu makes the file and then locks it (bsd/vfs/vfs_syscalls.c open1), so the maker fails busy
  and never holds it, and the one that holds it found it, did not make it, and leaves it at its drop
  (`test_creators_racing_a_lock_files_removal_never_both_hold_it`). Either way a user's open of the name is still
  refused for want of the switch's socket, and the next creator opens the file as it is and leaves it.
- **macOS jailer: a root supervisor per jail, for the freezer.** macOS has no cgroup freezer, so every jail gets a
  supervisor: a fork of the jailer made just before the exec, which stays root (`pid_suspend` needs root), in a
  session of its own, chrooted to `/var/empty`, with only its standard descriptors (standard error is
  Firecracker's), the jail's directory and a pipe to the jailer. It reads one file that only root can write, by
  name in that directory: no link followed, only a regular, root-owned file with one link that root alone can
  write, at most 64 bytes, its content driving no allocation. It writes `cgroup.events` and, after a value not in
  the kernel's form, the control file itself, in place and only while it holds what was read. For that write it
  sets the file's user-immutable flag and lifts it again (16 microseconds on average), so that another writer's
  open is refused with `EPERM` rather than its write lost; only root, the file's owner, can set or lift the flag;
  killed with SIGKILL in that moment it leaves the file immutable, which `chflags nouchg` or the next jailer on
  that directory lifts (`test_a_supervisor_killed_while_writing_back_leaves_a_removable_jail`). It suspends and
  resumes the jail's processes, known by pid and start time; it execs nothing and reads no environment. The jail
  cannot reach it: it is outside the chroot and root's, and Firecracker's sandbox allows signals to itself only.
  It ends
  with the jail and ignores every signal it can; if it cannot freeze a process of the jail, it kills the jail.
  Root can SIGKILL it, which leaves the jail as it is (a frozen jail stays frozen until root kills it) and
  releases its lock on the jail's directory; on Linux the freezer is the kernel's and cannot die
  (`test_supervisor_protocol`, `test_supervisor_fails_closed`, `test_files`, `jailer-test freeze`).
- **Windows jailer: the freezer rests on an undocumented job information class.** Every jail gets upstream's
  freezer files next to its root (`freezer.state`, or `cgroup.freeze` and `cgroup.events`), with a DACL that grants
  SYSTEM, the administrators and the operator, nobody else: the jail cannot write them (`jailer-test.ps1 freeze`).
  The jailer, which stays for the jail's life, reads the control file by name with no reparse point followed, takes
  only a regular file with one name owned by SYSTEM, the administrators or the operator, at most 64 bytes, and
  freezes or thaws the jail's Job Object. The class that does it, `JobObjectFreezeInformation` (18), is not in
  Microsoft's documentation (the SDK lists it as reserved); its layout is System Informer's (phnt `ntpsapi.h`). It
  was measured on Windows Server 2022 build 20348 and Windows 11 build 26300, elevated and not
  (`tools/windows/job-freeze-probe.ps1`), and the freezer stage passed on both (elevated on build 20348, unelevated
  and elevated on build 26300 with kit 8d577b7: `jailer-test.ps1 freeze`). Because Windows does not promise it, every jail's start first freezes a
  throwaway process in a job of its own and checks that its CPU time stands still; where that fails, on a build that
  changed it, no jail starts, and the error names the NTSTATUS and the build (`test_self_check`). A freeze or thaw the
  file asks for that fails kills the jail rather than leave it against the request (`test_a_failed_freeze_fails`).
  The jailer's death kills the jail, frozen or not (its job is killed on close); on Linux the freezer is the
  kernel's and cannot die.
- **Windows jailer: IP networking is denied with `--netns` only.** A jail given a network (`--netns <dir>`) gets
  none of the host's IP networking: the Windows Filtering Platform blocks the jail's binary at every connect, bind,
  listen and accept layer, in a session that ends with the jailer (`jailer-test.ps1 netns`). A jail without the
  flag keeps the host's IP, as a Linux jail without it keeps the host's namespace; there seccomp's `socket` domain
  rule still limits Firecracker to Unix sockets, and the mitigation profile has no counterpart of that rule yet
  (docs/PORTING.md, row 2). `--netns` needs an elevated jailer, as `setns` needs root. Without the
  jailer, Windows confinement is the mitigation profile only (no jail directory, token or Job Object).
- **macOS jailer: two jails of one uid in one network are kept apart by the sandbox profile, not by the kernel's
  file checks.** Each jail given a network directory has its endpoints in a directory of its own there
  (`<dir>/<id>/`), which grants the jail's uid and the directory's owner only, so a jail of another uid gets nothing
  there. macOS knows a jailed process by its uid alone, so two jails of one uid are told apart only by each
  Firecracker's sandbox profile, which names its own directory (`test_jail_network_profile_limits_sockets`). An
  endpoint also sends its guest's frames only to sockets directly in the network directory that its owner or root
  owns, the switch's, and drops other senders' datagrams (`test_a_jails_endpoint_takes_only_the_switch_as_a_peer`),
  so a jail of the same uid that broke its profile still reads no frame of another's. It can inject: a Unix
  datagram's sender address is the path the sender wrote, which a process can forge from its own root, and macOS
  gives datagram sockets no peer credentials (xnu bsd/kern/uipc_usrreq.c, `LOCAL_PEERCRED` is a stream's). The
  network directory's owner is trusted for that network, as whoever holds CAP_NET_ADMIN in a namespace is on Linux.
  Use one uid per jail, as upstream advises. So that a switch started or restarted after a jail is reachable,
  the jails' uids are granted write, and nothing else, on every file made directly in the network directory, not on
  sockets alone: keep nothing there but the switch's sockets and their lock files
  (`test_each_jail_has_a_network_directory_of_its_own`; a jail's write right on a lock file changes nothing, as its
  content is not read, and no jail may change its mode: `test_a_jail_reaches_only_lock_files_in_its_network`).
  A jail opens only the interfaces of its network: a name without `/` only if the switch's socket of that name is
  directly in the network directory, owned by its owner or root, with the interface's lock file beside it, which
  no jail can make there (the sandbox lets a jail read lock files there and make nothing:
  `test_a_jail_reaches_only_lock_files_in_its_network`; the jailer refuses a network directory the jail's uid
  owns or that its group, others or another uid's ACL entry may write: `test_the_jailer_refuses_a_network_others_may_write`,
  which passed as root on macOS 26 in CI runs 43784960688 and 43790310601 (it had failed in run 43688550565 for a
  test defect, its first case asking a refusal for root's own uid, which the rule exempts, fixed in f50fd8bc)
  (docs/COMPATIBILITY.md, Net hotplug);
  a jail of uid 0 may make one, its endpoint in its own directory and its lock file in the network directory, as
  root may make a TAP on Linux); and no path name, wherever it points (`test_only_the_operators_interface_opens`,
  `test_a_jail_opens_no_path_name`; `jailer-test netns`, root, not run yet). An interface is one Firecracker's at a
  time, a second open failing with `EBUSY` (the lock file's lock, which the kernel arbitrates), and the lock file's
  owner and mode say which uids and groups may open it, as a TAP's owner and group do (docs/COMPATIBILITY.md, Net
  hotplug), so a jail cannot take another jail's interface, nor hold one against the jail it was made for. A jail
  can tell which names exist directly in the network directory (it may look at their metadata, not list the
  directory), as a namespace's members see its interfaces on Linux.
- **Windows jailer: one network directory's jails are separated in code; the elevated stage has run on CI only.** On
  Linux two Firecrackers in one network namespace cannot reach each other's TAP: a TAP is its owner's, and a second
  attach is refused (drivers/net/tun.c, `tun_not_capable`, `tun_attach`). On Windows the network directory granted
  every jail given it full access, inherited by each endpoint made there, so one jail could take another's endpoint
  as its switch (receiving its guest's frames and sending to it), delete it, or take its name first. Now the
  network directory grants no jail anything, and each jail's endpoints are in a directory of its own in it,
  `<dir>\<id>`, which only that jail and the operator reach; a second jail of a running id is refused as busy
  (`jail_network`; `test_the_network_directory_grants_no_jail`, `test_each_jail_has_a_network_directory_of_its_own`, `test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint`: written, compiled and unit-tested on CI).
  A jail refused by Windows itself is shown by `jailer-test.ps1 netns` (elevated: a probe given another jail's
  network could not connect to, delete or take the name of that jail's endpoint, nor make a name in the network
  directory; a second jail of a running id refused, the first keeping its endpoint) and `jailer-test.ps1 netguest`
  (a jailed guest's frames through its endpoint), both passed in CI run 43442912128 (861d365; Windows Server 2025
  10.0.26100.33674 on an AMD EPYC 7763, elevated). Not run elevated on a PC: the PC's run at 861d365 was
  unelevated, where both stages stop at the elevation they need.
- **Windows jailer: the jail's token does not confine devices or the system's services.** It confines files,
  processes and, given a network (`--netns`), IP. On Linux the chroot leaves the host's files out of reach. A
  Windows jail is a drive letter of its own: every other path stays reachable, and only the jail's token confines
  it. Its restricting SIDs are the jail's own SID and four groups every process of the session has: Everyone,
  Users, Authenticated Users and Interactive (overlay/jailer/platform/windows/mod.rs, `RESTRICTING_SIDS`). A
  restricted token is granted only what both its enabled SIDs and its restricting SIDs are granted (Microsoft,
  CreateRestrictedToken), so a jailed Firecracker reaches what those groups are granted:
  - **Files and registry.** It reads the Windows directory, Program Files, files under ProgramData,
    `C:\Users\Public` or a data volume, and HKLM registry keys that grant one of the four groups read. Its integrity
    level, below medium, keeps it from writing those files and keys, and the user's own files stay denied
    (`jailer-test.ps1 isolation`).
  - **Devices, services and names, measured from inside a real jail on Windows Server 2022** (`fs-probe devjail`
    under the jailer):
    - 87 of the host's 174 device objects open, each driver's I/O-control code reached. Windows has no counterpart of
      seccomp's list of allowed I/O-control numbers.
    - It reads and writes the host's serial ports, which `--netns` does not close.
    - It reads the system disk's serial number, the partition table and every mount point.
    - It connects to 147 RPC/ALPC endpoints, LSA's, SAM's and the service control manager's among them, and opens
      17 service pipes, the spooler's with write.
    - It maps 97 shared memory sections, Microsoft Defender's among them.
    - It makes named pipes and mailslots in the session's namespace.
  - **What it does not reach.** Raw disk and volume reads and physical memory are refused.
  - **Not measured.** No step out of the jail was found, but none was looked for: the drivers' and services' own
    checks were not attacked.
  - **Linux, for comparison.** A Linux jail has `/dev/kvm`, `/dev/net/tun`, `/dev/urandom` and `/dev/userfaultfd`
    behind a list of allowed I/O-control numbers.
  - **Not done yet: the jail's own SID as the only restricting SID.** Measured under that token: 13 device namespaces
    (those without `FILE_DEVICE_SECURE_OPEN`) and no RPC endpoint, service pipe, section or name of its own making.
    It needs every DLL and registry key Firecracker uses to be loaded before `RevertToSelf` (in place: the preload
    step 1's trace found runs before the revert, and a step that fails stops the start, named), and WHP to work
    under it. WHP does not, measured: it reports no hypervisor, as `\Device\VidExo` grants Authenticated Users and the
    `hypervisorPlatform` capability, not the jail. Opening WHP's two devices is not what it needs: with Authenticated
    Users and Everyone both open and WHP still reports no hypervisor; with Authenticated Users and Users
    `\Device\HvService` is denied and WHP runs. Two ways work: a partition made and set up before `RevertToSelf` runs after
    it under the jail's SID alone (option P), and an AppContainer with the `hypervisorPlatform` capability runs WHP
    fully (option Q), as does an LPAC with it, which reaches four devices (`fs-probe jail-variants`). Option P's
    record did not settle it: its vCPU's run did not return under the emulated local APIC. Which one, and what each
    leaves reachable, is measured next (`fs-probe whp-token`,
    `fs-probe jail-variants`; docs/windows-jail-reach.md).
  - **The plan this replaces cannot be done.** ALL APPLICATION PACKAGES in place of the four groups:
    `CreateRestrictedToken` refuses it, ALL RESTRICTED APPLICATION PACKAGES and the `hypervisorPlatform`
    capability SID as restricting SIDs with error 87 (`fs-probe jail-variants`, `fs-probe whp-token`). WHP refuses
    an AppContainer token only without the `hypervisorPlatform` capability (`E_ACCESSDENIED`); with it, WHP runs.
  - Then a less-privileged token for the API process, which needs no WHP.

  The measurements, per device and per kind of object, the comparison with Linux and the fix's plan:
  [docs/windows-jail-reach.md](docs/windows-jail-reach.md).
- **Windows jailer: a file a jail shares gets read and write, nothing more.**
  - **What changed.** A file hard-linked into a jail's root, or a bind link's backing file, is one file for all its
    names. Each jail's SID now gets one entry of its own on it: `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
    (`0x12019f`). The full access the jail directory passes down to a hard-linked file is removed. Both happen
    before any process of the jail exists, and a file the jailer cannot narrow stops the start.
  - **What it was before.** The entry was full access, and the directory's inherited full access also stayed on the
    file. By the documented check of restricted tokens, a jail could then have rewritten the DACL of a file that
    other jails and the operator hold, taken ownership of it or deleted it. Not exercised.
  - **What stays after a jail.** A hard-linked file keeps the last jail directory's inherited entries (the system,
    the administrators, the user) and the jail's label, integrity level `0x1800`, on every name of it, the
    operator's included. On Linux, an inode's owner and mode are likewise one for all its names. Copy what must keep
    its security; hard-link only what is the jails' to share.
  - **Test:** `jailer-test.ps1 shared` (three jails on one file; not run yet) and
    `test_a_file_shared_by_two_jails_keeps_both`.
  - **Details:** [docs/windows-jail-reach.md](docs/windows-jail-reach.md), "Files a jail shares".
- **Windows jailer: a parent cgroup's name is not the jail's to take.** A `--parent-cgroup` is a named Job Object
  that later jails join by its name. In the session's object namespace a process that may make an object there
  could make a job of that name first, for later jails to join a job of its own or be refused. So the jobs are
  named in a private namespace whose boundary is the operator's SID at medium integrity, with a security
  descriptor that grants the system and the operator and lets nothing below medium read or write: a jailed
  process, at integrity level 0x1800 and on a token restricted to SIDs it grants nothing, neither makes a
  namespace of that boundary ("A process can create a private namespace only with an integrity level that is equal
  to or lower than the current integrity level of the process": Microsoft Learn,
  AddIntegrityLabelToBoundaryDescriptor) nor opens the one that is there
  (`test_a_jails_token_does_not_reach_a_parents_name`, on a thread with the jail's token: both refused with access
  denied on Windows Server 2025, CI run 43385227122; `jailer-test.ps1 parent`, from a jailed process: the open and
  the making both denied with Windows error 5, in CI run 43442912128, 861d365, elevated, and on the PC at 861d365,
  Windows 11 build 26300, unelevated). The namespace lasts while any process has it open, whoever made it: with a second process holding
  it, the process that made it closes its handle and opens it again, and once the second process has gone and
  the last handle is closed it is not found (error 3), so a jailer started after the operator's tool has gone
  finds the parent's job while a jailer still holds it (the same test, with a second process, asserted: Windows
  Server 2025, CI run 43388798760; Microsoft Learn, CreatePrivateNamespaceW, speaks of the maker's handle
  alone). Once nothing holds it, the next jailer makes the namespace and the parent's job anew, without the
  parent's limits, as the compatibility table says of a parent's life. A job the jailer did not make is still joined only when the
  operator, the administrators or the system own it and it is not labelled below medium
  (`test_a_parent_made_below_medium_integrity_is_refused`).
- **Windows jailer: `memory.max` bounds memory in sections at the jailer's next count, not at once.** The jailer
  sets `memory.max` as a Job Object memory limit, which charges private memory only. Sections (pagefile-backed, or
  of a file: wick's memfd is a temporary file's) are not charged to the job, and the jail's token does not stop a
  process making them: under a job limit of 32 MiB a jailed process stopped after 30 MiB of private memory but
  mapped and wrote 256 MiB of each kind of section (`jailer-test.ps1 sections` before the count, measured elevated
  on Windows Server 2022; with 4 GiB of
  sections the host's commit grew by 4.1 GiB while the job's peak stayed at 9 MiB; the same on Windows 11 build
  26300, elevated, kit 7952d31, 2026-11-13: private memory denied after 30 MiB, 256 MiB of each kind of section
  allowed). A memory partition tied to the job does not charge sections either: under a partition of 256 MiB,
  private memory stopped at 254 of 512 MiB and sections of each kind reached 512 of 512, the partition's
  committed count 0 after (tools/windows/memory-partition-probe.rs, the kit's `memory-partition-probe.exe 256`,
  same PC and day). A compromised jailed
  Firecracker can so take host memory past its limit, and guest memory backed by a memfd (with vhost-user
  devices) is not charged either. Anonymous shared memory that wick maps (`MAP_SHARED | MAP_ANONYMOUS`) is now
  charged, as Linux charges a shmem page when it is touched: its section is reserved, and each page is committed
  at its first access together with a page of private commit that pays for it, so the job refuses at
  `memory.max` and the process ends with 137, as for private memory
  (`test_shared_memory_past_the_job_limit_ends_the_process`, which passed in CI run 43521200989;
  `test_anonymous_shared_memory_is_charged_at_first_touch`, which passed in a process of its own in CI run 43524342863, b85b5a4, and each saved run since). A touched page so takes twice its size of host commit and once of memory.
  The userfaultfd restore's section is charged the same way: reserved at the registration, each page committed with
  its charge when the handler fills it, and a fill that `memory.max` still refuses after the reclaim ends the VMM
  with 137, as Linux's memory cgroup kills it at the copy it cannot charge
  (`test_a_fill_past_the_job_limit_ends_the_vmm_with_137`; before, the fill was `ENOMEM` and the VMM went on: the
  memory.max row). A 2 MiB chunk discarded whole with `MADV_DONTNEED` (free page reporting; the section is one
  per chunk) gets a new, empty section, so its commit and charge go
  (`test_a_wholly_discarded_chunk_gives_its_section_commit_back`, passed in CI run 43545368906, 305a806). A page discarded in a chunk not discarded whole
  (balloon inflation's scattered pages) keeps its section page committed (a SEC_RESERVE page cannot be decommitted)
  and its charge with it, so that what the jail is charged is never less than the host commit it holds
  (`test_registered_memory_is_charged_as_it_is_filled`; passed in CI run 43545368906, 305a806, and each saved run since). The
  guest has such a page back at once, its fill taking nothing new (made with no room left, no reclaim asked), while the
  job and the jail's count read the dead pages, exactly, more than Linux's memory.current until their chunk moves or is
  discarded whole, never past `memory.max`, as each was charged within it
  (`test_a_scattered_discard_keeps_its_charge_and_its_refill_takes_none`, on Windows Server 2022 20348). A reclaim of
  such pages before a charge is refused at the limit, as Linux's memory cgroup reclaims, moves their chunks into new
  sections, and works with no room left in the job: a move's maps take none (its view of the new section mapped into the
  move slot, the chunk's views swapped one at a time, above; a view mapped anywhere took commit for its page tables,
  VIEWCHARGE, and a move gave back 12 KiB of its dead pages' charge for them first until review B3), and a chunk with
  one dead page moves; the fill it was for is made, but where its charge page is the first committed in its 2 MiB
  region, which takes a page table too, 8 KiB where the move gave back 4, and is refused, as Linux charges a fault's
  page table to the memory cgroup (v6.1 include/asm-generic/pgalloc.h :8 and :85)
  (`test_a_chunk_with_one_dead_page_at_the_limit`; the memory.max row, on Windows Server 2022 20348, and on Windows
  Server 2025 in CI runs 43680983973 and 43688550565). Under a running vCPU it is not shown yet: the test of that,
  MOVEUNDERVCPU, moved no chunk in those runs, its fill at the limit a discarded page's, which takes nothing new;
  with a fresh page's fill since, it ran in CI runs 43784960688 and 43790310601 and failed: a thread's stack page was
  refused at the limit before any chunk moved (exit 137, the stack filter's line), with no reclaim first where
  Linux's memory cgroup reclaims for a stack page too: the vCPU thread's, inside WHP's run call (its RUNREC lines in CI's
  windows job at b55b2673: 52 KiB committed from 8). A vCPU thread's first run now commits its stack 112 KiB below the frame that called it (twice the deepest mark on record, 47.2 KiB in CI's windows job at e6c08999, plus 16, rounded up to 16: `vcpu::RUN_STACK`),
  far from the limit, so that WHP's growth within that depth asks no commit there
  (`test_a_vcpu_threads_stack_is_committed_before_its_first_run`, at 96 KiB in CI's windows jobs at 57b122f9 and
  e6c08999: 97 KiB committed below the frame that called run after the first run, from 5; MOVEUNDERVCPU is the proof
  under a move, and passed in both, every round moved at the limit and no value lost, its marks printed at e6c08999;
  at 112 KiB, in CI's windows job at 80589c69, 112 KiB committed below that frame after the first run, from 4, and
  MOVEUNDERVCPU 40 of 40 rounds moved at the limit, no value lost, its deepest mark 47.2 KiB again). An interim until the stack reclaim (the memory.max row); it covers no other thread: the
  userfaultfd serve thread's stack, refused inside ntdll's heap code at the limit, still ends the VMM with 137. A move
  that Windows refuses a step of before its first unmap (its new section, its view's map into the slot, its live
  pages' commit or closing, its alias's first unmap) is not made and leaves the chunk and its charge as they were,
  said on standard error, and the reclaim goes on to the next chunk; with none, the commit that needed it is refused
  as without a reclaim (`test_a_move_not_made_leaves_its_chunk_as_it_was`; each step refused by the test, on
  Windows Server 2022 20348 and 2025 26100). The reclaim runs on its own thread with its 64 KiB stack
  committed at creation, so it grows no stack at the limit; the touching thread's own path to it is 8976 bytes deep
  on record (RECLAIMSTACK, Windows Server 2022 20348 and 2025 26100); a thread whose stack has less committed below its frame, and cannot grow it at the limit,
  ends the VMM with 137 (below), but while a reclaim is under way: a move holds its new section's commit until its
  end, and a thread holding none of wick's memory locks whose stack page is refused in its middle waits for the
  move's end or the reclaim's, at most 1 s, makes its guard pages again as `_resetstkoflw` does, and goes on
  (`test_a_stack_page_refused_during_a_move_is_had_once_it_ends`; every refused stack commit is asked for once more,
  with no wait where none is allowed, so a page refused in a move's middle whose handler runs after the reclaim's
  end has the room back: `test_a_stack_page_refused_as_the_reclaim_ends_is_had`; a thread holding such a lock does not wait, as the
  reclaim takes them, nor does the reclaim's own: `test_a_stack_page_refused_with_a_lock_held_is_not_waited_for`,
  `test_the_reclaimers_own_stack_page_is_not_waited_for`; a refusal after the wait ends with 137, its line saying
  it waited: `test_a_stack_page_refused_again_after_the_wait_ends_with_137`,
  `test_a_stack_page_waits_for_a_move_that_does_not_end_to_its_bound`; all on Windows Server 2022 20348 and 2025
  26100). The line that ends a VMM at the limit (`out_of_memory`) is written after 256 KiB of commit set
  aside for it is given back, so its stack can grow.
  Not before a commit made at once (`MAP_POPULATE`, a
  private file mapping's read, a `MAP_FIXED` recommit, a discard of private memory that is not lazy, a committing
  `mprotect`) or an allocation of the VMM's own (its heap, a thread's stack with no reclaim under way): those are refused at the limit with no
  reclaim first (`ENOMEM`, or the process ends: a thread whose stack must grow ends it with 137 and a line, its
  refused commit told from a stack used up by the thread's TEB in an unhandled-exception filter, which bypasses
  Windows Error Reporting on purpose, as an end at the limit is not a crash; a stack used up still reaches it,
  `test_a_stack_that_must_grow_at_the_limit_ends_with_137`; a stack used up gets a line from the same filter and
  ends with 0xC00000FD on every kind of thread, the filter ending it in a job of the jailer's limits and Windows
  Error Reporting out of one: `test_a_stack_overflow_at_the_reserves_end_is_still_one`, on Windows Server 2022 20348
  and 2025 26100; see Fixed defects below),
  not done yet for the reclaim; the limit holds either way. A move holds its live
  pages in two sections for its
  time; a 2 MiB move budget of private `PAGE_NOACCESS` commit, made at the first registration with the move slot
  (20 KiB more, its anchors and their page tables: 2068 KiB in all, `test_a_moves_temporary_view_takes_no_commit`), is the cover the
  jailer's count takes off for them, so the count, and the bound it enforces, stays exact during a move
  (`test_the_jailers_count_does_not_rise_during_a_move`; its runs in the memory.max row). A page discarded while a system
  call copies it (a guest that balloons a buffer a device is still using) would fail that call, where Linux's copy
  faults the page in again: so a discard waits for the calls in flight on its range, and a call that may wait without
  end (a blocking socket's or pipe's) copies through a buffer of its own, so that no discard waits on it (the
  `mem_backend: Uffd` row;
  `test_a_discard_waits_for_a_read_in_flight_on_its_range`, `test_a_blocking_read_does_not_hold_a_discard`; passed
  in CI runs 43612093006, 8ff63d4, and 43616040593, 5e3727d). Firecracker never met it, its devices' calls and the balloon's discards running on one thread; the
  wait is for the reclaim at the limit, which would move chunks on whichever thread touched memory there (a vCPU's
  among them; at a real job limit shown on host threads, not yet under a running vCPU), and other users of the
  compat libc. The reclaim's move of a chunk is held off by a call only in its copy, from right before its kernel
  call to its end; a call in its prefault, which may wait for the handler's next fill, holds nothing, as the move
  keeps what the prefault made present (`test_a_fill_moves_a_chunk_a_call_waits_in_its_prefault_on`), and its turn
  to its copy waits for a move under way, decided under one lock with the move's start
  (`test_a_call_turning_to_its_copy_waits_for_a_move`). A fill or a touch at the limit whose reclaim passed over
  such a chunk claims it, waits for the calls in their copy without the userfaultfd's lock, and moves it; a fill
  then goes on where it was (`test_a_fill_waits_for_a_call_in_its_copy_then_reclaims`,
  `test_a_fill_resumes_after_its_wait`, `test_a_fill_against_a_reading_loop_is_made`, on Windows Server 2022 20348
  and 2025 26100; each ended the VMM with 137 before, where the fill did not wait). A fill still refused with
  nothing reclaimable left ends the VMM with 137, named (`test_a_fill_with_nothing_reclaimable_ends_named`).

  Sections made around wick (a compromised Firecracker's) are counted by the jailer
  (overlay/jailer/platform/windows/commit.rs): every 1 ms, over the job's processes, private commit plus section
  commit (`PROCESS_MEMORY_COUNTERS_EX2.SharedCommitUsage`, which counts a section for whoever holds a handle or a
  view of it, a closed handle with a view kept included: SECTREC-e shared, PC b4717ec), less the committed
  `PAGE_NOACCESS` private memory that pays for wick's own sections (no more than the section commit) and the large
  pages the jailer gave; past `memory.max` the jail is ended with 137 and the jailer names the count
  (`jailer-test.ps1 sections`, `test_a_section_past_the_limit_ends_the_jail_with_137`,
  `test_charge_pages_pay_for_the_sections_they_cover`; passed in CI run 43545368906, 305a806, and each saved run since,
  and on the PC at 305a806 and df0bf87). A process of the job the jailer
  cannot open or read ends the jail the same way. What a compromised Firecracker can still do:
  - **Take host commit past the limit until the jail is ended after the next poll**: between two polls section commit is not bounded in bytes, only by the time to the next poll, which is the host's scheduling: on a loaded CI runner two polls were 6090 us apart (`jailer-test.ps1 sections`, before the count's thread was raised: the run is in docs/COMPATIBILITY.md's `memory.max` row). The count's thread is now time-critical (`THREAD_PRIORITY_TIME_CRITICAL`, above every thread of the jail): on fc-win (Windows Server 2022 20348, 8 vCPUs) with one spinning thread per CPU at normal priority, a normal-priority poll loop's gaps had a median of 16.0 ms, a 99th percentile of 157 ms and a greatest of 173 to 188 ms (1060 to 1089 of 1999 past 2 ms), and the time-critical one's a median of 976 us, a 99th percentile of 1.47 ms and a greatest of 1.50 and 1.52 ms (none past 2 ms), as on the idle host (POLLGAP, `test_poll_gaps_under_load_on_record`, 2000 polls each, three runs in one boot). The jailer's line at a kill names how late its tick woke this poll and the one before, and how long the one before took. The window from a section's creation to a jail that can take no more: to the next poll (every 1 ms on a schedule: COMMITTIMER, 500 ticks in 500 ms, median 1039 us, greatest 2725 us, in CI run 43616040593, 5e3727d, where Windows' periodic timer of 1 ms, the control, took 761 ms for 500), that poll's count with the cover read again (160-185 us), `TerminateJobObject` (265 us in one run, 7740 us in another) and the processes' end after it (876-979 us): 1374 us and 9830 us in all on the PC at df0bf87 (COMMITPOLL, debug and release, one run each), and 1950 us in CI run 43616040593 on the schedule (`TerminateJobObject` 59 us, debug); what a process commits during the call and after it, and the call's own time over 50 rounds, alone and after a freeze of the job, is TERMREC's (`test_terminating_a_jail_on_record`; in CI run 43616040593, debug, 50 rounds each: a process committing as fast as it can committed 192 to 384 KiB during `TerminateJobObject`, a median 74 us, and none after its return, ending a median 2096 us later; with the job frozen first it committed 192 to 448 KiB during the freeze, a median 58 us, and none during the call; a suspended process ended a median 383 us after the call) (`test_the_poll_timer_ticks_about_every_millisecond`, `test_a_section_past_the_limit_ends_the_jail_with_137`). Windows tells no user-mode process of a
    section's creation and charges it to no job or quota (SECTREC-a, and SECTREC-e quota and shared, PC b4717ec,
    `test_section_memory_and_a_charge_for_it_on_record`; `ObRegisterCallbacks` takes process, thread and desktop
    handles only, Microsoft Learn, `OB_OPERATION_REGISTRATION`), and a 4 GiB section is made in 27.8 us
    (SECTREC-e c). Linux charges each page before it is mapped (v6.1 mm/memcontrol.c, `try_charge_memcg`). An OS
    limit; RAM touched in the window is bounded by how fast the process writes.
  - **Hold up to twice `memory.max` of usable memory for up to 100 ms**, by freeing the `PAGE_NOACCESS` commit the
    count took off and committing as much usable private memory between two reads of it (they come every 100 ms,
    whenever a process's private commit falls below its last read, and before any kill). Host commit is bounded by
    twice `memory.max` at all times: what is taken off is commit the job charged. To close it, the read on every
    poll, which costs about 0.8 ms for a jail laid out as Firecracker's (SECTREC-d, PC 2be20a5): not done.
  - **Move commit out of the jail through a peer that pulls handles**: a userfaultfd handler or a vhost-user
    backend that receives descriptors pulls the handles a jailed sender offers (`sock_ctrl_msg`, `FLAG_PULL`), and
    a section's commit then counts for the peer (SECTREC-e: the charge follows the holder). On Linux a shmem page
    stays charged to the cgroup that faulted it, whoever holds the descriptor (v6.1 mm/shmem.c). Bounded today by
    when the peers receive (the userfaultfd handshake, vhost-user's memory-table messages) and by their receive
    room (descriptors past it are closed). To close it: the receiving side refuses a pagefile-backed section from a
    sender in another job unless its protocol carries one, and counts what it took; not done.
  - **Guest memory backed by a memfd** (with vhost-user devices) is a temporary file's section, page cache, which
    the count leaves out as it leaves out a file's (Linux reclaims page cache at `memory.max` rather than ending the
    process); a memfd is shmem on Linux, charged. To close it: a charge at first touch, as for wick's anonymous
    shared memory; not done.
  - **Under a parent cgroup**, a memory limit on the parent is refused, by the operator's tool and the jailer
    (`test_a_parent_with_a_memory_limit_is_refused`): sections are counted against each jail's own `memory.max`, not
    a parent's, so a parent's limit would be weaker than its name. Counting a parent's jails together is to come.
  - **Large pages**: the count takes off the bytes of large-page sections the jailer gave (hugetlb's on Linux,
    bounded by `hugetlb.2MB.max`), on the reading that `SharedCommitUsage` counts a large-page section as any
    pagefile-backed one; not measured. If it does not, up to `hugetlb.2MB.max` of other sections go uncounted. To
    settle it: `jailer-test.ps1 hugepages` reading the jailed process's `SharedCommitUsage` with the guest on large
    pages; not done.
  - **On a host without `SharedCommitUsage`** (Microsoft Learn gives `PROCESS_MEMORY_COUNTERS_EX2` for Windows 10
    22H2 and Windows 11 22H2, each with the September 2023 cumulative update, and later; no server is listed), the
    jailer cannot count sections, so `memory.max` is refused there: the jailer proves the count on the host (a
    section made and counted) when it reads the limit, and stops before any jail is made, naming the cause
    (`test_a_memory_limit_is_refused_where_sections_cannot_be_counted`; on Windows Server 2022 20348 itself,
    `test_a_memory_limit_on_this_host`, where the tests that stand on the count say they cannot run, naming the
    build).
- **Windows jailer: the handle limit holds only in the jailed process.** Upstream's jailer limits Firecracker to
  2048 descriptors by default (`RLIMIT_NOFILE`), and the kernel enforces it. Windows has no per-process handle limit
  to set: a process's pool quota is accepted and ignored (200,000 handles made after a 1 MiB paged-pool quota,
  measured on Windows Server 2022), and a Job Object has no handle limit and its memory limit does not count
  handles (a jailed process opened 100,000 files under `memory.max` of 32 MiB). The Windows jailer gives each
  jailed process `--resource-limit no-file=` (2048 by default) in its environment, and wick's POSIX layer fails a
  call that would make descriptors past it with `EMFILE`, counting the process's handles, Windows' own among them
  (crates/compat/libc, `wick_nofile`, which names what it does not cover). That holds a well-behaved Firecracker
  to upstream's semantics. A compromised one makes handles with Windows' own calls, and nothing bounds those, or
  the kernel memory they take, short of Windows' fixed per-process maximum (2^24 handles, documented, not
  measured): `jailer-test.ps1 nofile` checks that the jailed probe still opens 5000 files under `no-file=512`, and
  100,000 under `memory.max` of 32 MiB with it (both opened in CI run 43442912128, 861d365, Windows Server 2025 on
  an AMD EPYC 7763).
  The bound a jailed process cannot pass, the jailer ending a jail whose handles pass the limit, is not written.
- **Windows: a pipe's maker gets no identity of Firecracker's, and a pipe's owner is an account, not a jail.** A
  path Firecracker is given may name a pipe (`\\.\pipe\<name>`, the counterpart of a FIFO for the log, the metrics
  and a serial device's output), and whoever made a pipe is its server, which Windows lets act as a client that
  opens it unless the client says otherwise ("The SecurityImpersonation level is the default for named pipe, RPC,
  and DDE servers": Microsoft Learn, Impersonation Levels). A FIFO's maker on Linux gets nothing of the kind. So
  Firecracker opens every path it is given at the anonymous level (`SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS`,
  "The server cannot impersonate or identify the client": CreateFileW): the log, metrics and serial output paths,
  the first time and each time a pipe is opened again, the drives, a pmem device's file, the config and metadata
  files, a snapshot's state and memory files, the kernel, the initrd and a seccomp filter file
  (`test_a_pipe_opened_by_path_gives_its_maker_no_identity`, `test_a_pipe_opened_again_gives_its_maker_no_identity`:
  a pipe's server calls `ImpersonateNamedPipeClient` on such an open and gets a refusal or an anonymous token, where
  an open without the flag, the control, gives it the impersonation level; CI runs 43372137748 and 43377614564,
  Windows Server 2025. Windows's answer there, from the tests' SQOSTEST lines of the second run: the control
  gives the pipe's maker a token at the impersonation level (2), and Firecracker's open leaves it with error 1347,
  `ERROR_CANT_OPEN_ANONYMOUS`, "Cannot open an anonymous level security token": it holds an anonymous token
  that it cannot so much as open, for the first open of a path and for a pipe opened again alike). For a file the
  same bit is `FILE_FLAG_OPEN_NO_RECALL`: a file of remote storage is read where it is, not brought back to the
  disk. What is not at parity: when a pipe's reader has gone, Firecracker gives what it kept to a new pipe of the
  name only if that pipe has the first pipe's owner, and an owner is an account. Two processes of one account are
  not told apart, two jails of one user among them: every jail's token has the user as its owner, and the jail's
  own SID is a restricting SID, which owns nothing and which a pipe's maker could write into a DACL itself, so the
  check has nothing of a jail's to compare. Processes of one account are one trust domain here, as two processes
  of one uid are for a FIFO on Linux (either may open it), with this difference: on Linux a FIFO is a file in the
  jail's chroot, which another jail does not reach, and a Windows pipe's name is the session's. What the jail's
  token gives: a pipe a jailed process makes with the token's default DACL grants SYSTEM, that jail's SID and its
  owner, so another jail's Firecracker, whose token must also pass by a restricting SID, is refused by it (from
  the token's construction; not measured for pipes); a pipe made with a DACL that grants everyone is opened. A jail
  can make pipes (measured from inside a real jail, `fs-probe devjail`; docs/windows-jail-reach.md), so once the
  first reader has gone it can take the log or metrics another jail of the same user wrote meanwhile (up to 64 KiB),
  if it knows the name; the fix planned there takes that right away from the jail. Run each jail's pipes under
  names the others cannot guess, or run tenants under different accounts.
- **Windows: a resident page made `PROT_NONE` before a register is taken as missing.** The register takes a page's
  residency from `mincore`, whose working-set query (`QueryWorkingSetEx`'s `Valid`) does not count a
  `PAGE_NOACCESS` page, so such a page becomes missing, and its contents are not what a fill or an access then finds,
  where Linux's `mincore` counts a present `PROT_NONE` pte (mm/mincore.c v6.1 :129 to :130; arch/x86 `pte_present`
  :735 to :738) and the register changes no page
  (`test_a_resident_page_made_prot_none_keeps_its_contents_through_a_register`, ignored citing this entry: "the
  resident PROT_NONE page is missing" on Windows Server 2022 20348; on main a33f5aba the same check, one line for
  both pages then, failed: "a resident page is missing"). Firecracker registers guest memory it has just mapped
  (src/vmm/src/persist.rs `guest_memory_from_uffd`: `memory::anonymous`, then `register` of each region), so no
  page of it is resident and closed then.
- **Windows: memory mapped over part of a registered mapping is not registered, and a range must lie in one
  mapping.** `MAP_FIXED` over part of a registered mapping is `EINVAL`, where Linux maps it
  (`test_a_page_mapped_over_and_registered_again_is_filled_in_the_new_memory`, ignored citing this entry); a register
  that spans two mappings is `EINVAL`, and one that overlaps a registered range without lying inside it, or holds a
  page of it that was unmapped or mapped over, is `EBUSY`, where Linux registers each vma: a range is one section
  with its alias, made over one whole private mapping and kept until all of its memory is unmapped. Part of a
  mapping is registered, as Linux's register splits the vma, since the commit that changed this entry: the register
  moves the whole mapping into its sections and registers the part's pages only; the rest of the mapping is in no
  registration and keeps what it holds, a page outside the working set included
  (`test_part_of_a_mapping_is_registered`, `test_memory_mapped_over_part_of_a_mapping_is_registered`,
  `test_a_part_registered_is_charged_as_the_whole_mapping_would_be`,
  `test_parts_of_a_mapping_register_with_two_userfaultfds`,
  `test_an_munmap_of_a_registered_part_leaves_the_rest_of_the_mapping`,
  `test_a_part_registered_keeps_the_rest_of_the_mapping_out_of_the_working_set`; first run: CI). Its cost: one copy
  of each page of the mapping that holds memory, and one read of each committed page outside the range that is not
  in the working set. Inside the range a page outside the working set is still taken as missing (the entry on a
  resident `PROT_NONE` page above has the same root; open). Memory registered once registers again, with any
  userfaultfd, after an unregister of any part of it or a release (an owner a page, the range's slot kept until its
  memory is unmapped: the `mem_backend: Uffd` row of docs/COMPATIBILITY.md, `test_memory_unregistered_whole_registers_again`,
  `test_memory_replaced_while_registered_registers_anew`; before, `EINVAL` on Windows Server 2022 20348 and 2025
  26100). Firecracker registers each region of its guest memory once, whole, and maps nothing over part of one.
- **macOS: a call Firecracker's own sandbox denies ends it by SIGKILL, not exit 148.** On Linux the seccomp trap's
  SIGSYS runs upstream's handler, which logs the bad system call, counts `seccomp.num_faults` and exits 148.
  Seatbelt has no action that traps the calling thread, and a signal the process can catch let the denying thread
  run on, and let code in the process keep it alive (the system call filter row above), so the kernel ends
  Firecracker inside the call, by SIGKILL, with the exit reason `OS_REASON_SANDBOX` and a crash report
  (`test_a_denied_call_never_returns_to_its_thread`). That fails closed, but a supervisor that looks for exit 148,
  or a reader of the metrics that counts faults, sees neither; the record is the exit reason, which Firecracker's
  parent reads before it reaps it (docs/COMPATIBILITY.md, the denied-call row), the kernel's sandbox log line and
  the crash report. A denial in the API process already has upstream's end in full, since Firecracker is its
  parent (`test_a_denied_call_in_the_api_process_ends_firecracker_as_its_own`). Fix: a supervising parent of the
  VMM that does the same for it (the line, the metric, exit 148), proven by the same test against the VMM; it waits
  on a decision.
- **No per-thread filters outside Linux.** Neither macOS nor Windows filters system calls per thread. Threads of a
  process share its address space, so the union of upstream's filters applies process-wide, and the API server,
  whose separate filter is a real boundary, moves into a process of its own. On macOS that is in place: the API
  socket's HTTP server and upstream's request parsing run in a process sandboxed as upstream's `api` filter (its
  system calls only, no files, no shared memory, no executable mappings), and Firecracker's API thread handles the
  requests it passes on with upstream's code; either process's end ends the other (`test_api_profile_*`,
  `boot-test api-process`), also a Firecracker killed right after the fork, before the API process watches for
  its end: the API process is given Firecracker's pid from before the fork, and no longer asks for its parent's
  once it runs, which is launchd's by then (`test_an_api_process_orphaned_before_its_watch_ends`). A call the API process's sandbox denies ends Firecracker with the bad-syscall code,
  its log line and metrics, as the API thread's trapped call does on Linux: the kernel kills the API process inside
  the call, and Firecracker, its parent, reads the exit reason before it reaps it, which only a parent may
  (`OS_REASON_SANDBOX`; XNU bsd/kern/proc_info.c `proc_pidexitreasoninfo`)
  (`test_a_denied_call_in_the_api_process_ends_firecracker_as_its_own`,
  `test_an_api_process_denied_before_its_watch_ends_firecracker_as_its_own`). Nothing the API process says or does
  makes its end a denial: an exit 148 or a SIGKILL from anyone else ends Firecracker as any other end of it
  (`test_an_api_process_that_exits_148_is_no_denial`). Every fork of the VMM and the jailer on macOS is made only while the process has one thread, the caller, and refused otherwise, naming the point and the count: the child has the calling thread alone, so a lock another thread held at the fork would stay held there for good (malloc's are reset by libmalloc's fork handlers; the Rust standard library's and the frameworks' are not). That covers the split of the API process (`ApiProcessError::Threads`), the jail's own fork of it, the sandbox profile's compiler, `--daemonize`'s two forks, `--new-pid-ns` and the freezer's supervisor and self-check (`test_the_jails_api_process_fork_refuses_a_second_thread`, `test_the_sandbox_compiler_fork_refuses_a_second_thread`, `test_daemonize_refuses_a_second_thread`, `test_new_pid_ns_refuses_a_second_thread`, `test_the_freezer_supervisor_refuses_a_second_thread`, `test_the_freezer_self_check_refuses_a_second_thread`); Linux's `--daemonize` is upstream's, unchanged. In a jail the two share the jail's memory and CPU limits, so together they stay within
  them (`test_limits_are_shared_with_the_api_process`; `jailer-test limits`, as root in CI's macos job on macOS 26.7.2, e7de455: a jetsam limit of 300 MiB split 268 + 32 for the API process, a CPU limit of 75% split 74 + 1). On Windows the same is
  in place without a fork: the API process is a second process from Firecracker's binary, made by Firecracker
  before its sandbox is set, or by the jailer in a jail on the jail's token and in its Job Object, with its end of
  the link and a handle to Firecracker inherited; it has the whole mitigation profile from its start, before it
  reads a byte from the socket (`test_api_profile_is_the_whole_profile_at_once`,
  `test_the_api_process_serves_under_the_api_profile`, `jailer-test.ps1 api`, and `boot-test api-process` on a WHP
  machine).
- **wick's host-side code is young.** The compatibility crates and the macOS and Windows backends (the
  Hypervisor.framework and WHP run loops, the userfaultfd kernel side, the network backends) have not had the years
  of review and fuzzing upstream's code has had, and have not had a third-party audit. Fuzzing has started: the
  virtio-net offload handling every non-Linux network backend uses (`vnet`) and the requests a userfaultfd handler
  process sends on macOS, and the Hypervisor.framework run loop's decoding of what a vCPU exit asks for
  (`hvf_exit`), have fuzz targets, which CI runs for a minute each
  ([CONTRIBUTING.md](CONTRIBUTING.md#fuzzing)), as do the interrupt controller the WHP run loop hands a
  guest's port and MMIO accesses to (`whp_irqchip`) and the WHP run loop's decoding of a vCPU exit (`whp_exit`). The run loops' own steps, which call Hypervisor.framework
  (`hv_vcpu_run`) or WHP, are not fuzzed.
- **The WHP x2APIC partition's #GP exit (option E, AMD hosts; in the code, off in the product until its held
  TSC-deadline write has run on Windows and a Linux guest has booted on it, so no product partition has it yet).** On one, every guest #GP, at any privilege level, leaves the
  hypervisor to the vCPU's run loop (`gp`), so a guest can make such exits at will (a ring-3 privileged
  instruction). The handler decodes at most 15 bytes from the exit context and reads at most three of the vCPU's own
  registers; it takes no lock another vCPU or the VMM's thread waits on, and neither allocates nor logs, so a storm
  of them costs that vCPU's thread, which runs under the jail's CPU limit like any guest work, as a guest's busy loop
  does. KVM intercepts every #GP the same way when `enable_vmware_backdoor` is set (Linux v6.1
  arch/x86/kvm/vmx/vmx.c 791, 5091-5103). The decode and the merge are unit-tested on every host (fuzz crate
  `whp_gp`); the storm's isolation is measured for its costliest #GP, the held LVT timer write below, by
  `jailer-test.ps1 x2storm` (X2STORM lines: a jailed 4-vCPU guest looping 10 s on that write against a port-write
  control, five runs, with the VM's API latency, its CPU with no `cpu.max` and under one CPU's, and a second jailed
  VM's 1 kHz loop rate). It has run on AMD in CI: before the gate the held LVT timer write failed its own legacy
  get with 0x80370308 in three of three windows-guest runs, always on vp 3; with the gate the storm holds with no
  refusal, three of three CI acceptance runs passing (every storm held, a write up to about 1,520 us), the 10 PC
  rounds not yet run. The exit path itself has run on Windows, in record builds only: GPEXITREC
  (`test_gp_exits_on_an_x2apic_partition_on_record`, a guest's #GP exits on an x2APIC partition) and
  `boot-test.ps1 x2apic` (a Linux guest booted on such a partition) passed on CI's AMD runners in CI runs 43680983973
  and 43688550565. Its LVT timer write in TSC-deadline mode is the one #GP that
  does more (option E-ii): WHP's register refuses that mode, and the APIC register page's get and set, the one other
  way, lose an interrupt requested between them (PC step 15a at 305a806,
  `test_a_page_set_loses_interrupts_and_the_held_lvt_timer_write_none`), so the handler holds every other vCPU of the
  VM out of the guest, suspends the partition's time and holds off the VM's host-side interrupt requests (a
  read-write lock that every `WHvRequestInterrupt` takes to read) while it gets the page, changes the entry, sets it
  and reads it back. A guest that loops on that write therefore stalls its own VM's vCPUs and delays its own devices'
  interrupts, for the hold's time a write (X2HOLDREC e, `test_a_held_lvt_timer_write_loses_no_interrupt`, on CI's
  4-processor AMD runners in CI runs 43680983973 and 43688550565, debug and release: 104 to 175 us a write with no
  other vCPU, 431 to 1853 us with 3 others, 3.3 to 8.8 ms with 15): a denial of service of the guest on itself, under the jail's CPU limit, which reaches no other VM and
  not the host, as a KVM guest that loops on an exiting instruction slows only its own VM. No rate limit is added, as
  KVM has none. The lock is taken after the hold, and a requester holds it only for its one WHP call and waits on
  nothing else meanwhile, so the hold adds no lock-order cycle. CI's x2APIC record build (kvm-ioctls'
  `whp-x2apic-record`), which turns option E on for `boot-test.ps1 x2apic`, is never shipped:
  `tools/check-record-features.sh` fails the release workflow and CI's kit if a product binary holds its line or a
  manifest turns it on.
- **Side channels** between VMs on the same host follow upstream's
  [production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
  guidance on Linux; the equivalent guidance for macOS and Windows hosts is not written yet.

## Planned: GPU access (no code yet)

wick has no GPU device today: `PUT /extensions/gpu` is refused as an unknown extension. The design
([docs/design-gpu.md](docs/design-gpu.md), roadmap M9) states now what a GPU-enabled microVM would add to the host's
attack surface, so that it is known before the feature exists. As designed, the feature would be off by default and
compiled out unless enabled, with the VMM's own sandbox unchanged.

- **The host GPU driver is reached by the guest.** In the first version a guest's Vulkan calls and shaders reach the
  host's GPU user-mode driver (in a sandboxed worker process) and, below it, the GPU kernel driver and firmware,
  without validation. A single driver bug can be enough to reach the host kernel. Later stages of the design add
  resource limits, a shader rewrite and a validation layer; none of them is in the first version.
- **One GPU per trust domain.** Guests that share a GPU, or a guest and host processes, can leak data through GPU
  local memory on affected GPUs (LeftoverLocals, CVE-2023-4969: Apple M2 (M1 not stated by the advisory; M3 fixed),
  AMD, Qualcomm) and through side channels (GPU.zip) that no software in wick can close. Upstream Firecracker says
  the same: "We can only run 1 customer workload securely per physical GPU"
  ([#849](https://github.com/firecracker-microvm/firecracker/issues/849)).
- **Windows: two open host differences, not decided.** These fall short of the rule of equal security on every
  host. Whether GPU ships on Windows with them is not decided:
  - A GPU worker there cannot have win32k lockdown, because the D3DKMT calls a GPU driver needs are win32k system
    calls. A compromised worker would reach all of win32k.
  - Windows bug-checks the host after five GPU hangs within 60 seconds (its default TDR keys), so several GPU
    microVMs together could take the host down.

  Both come from Microsoft's documentation and browser sandbox source; wick has not measured either. The options
  and their consequences are in the design (§2a).
- **No snapshots of a GPU microVM:** they would be refused.
