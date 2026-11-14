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
| System call filter | per-thread seccomp-BPF (upstream) | **in place:** a Seatbelt profile, process-wide, in upstream's two phases: until the microVM is built (when Linux installs the VMM thread's filter) it allows what building takes; then it narrows for good, as no extension can be issued, taken or released any more, to 102 system calls, 15 Mach traps and 7 kernel MIG routines (and `mach_exception_raise`, the kernel's own message for a thread's fault, below), each tied to the Linux rule it stands for, or to what libsystem calls on a path the rule's call takes (`__pthread_canceled`, which a cancellation point such as `read` or `nanosleep` makes when a handled signal, the vCPU kick's included, interrupts it with EINTR: it reads or sets the calling thread's own cancellation state only, XNU bsd/kern/kern_sig.c, and no thread can be marked cancelled, as `__pthread_markcancel` is in no list; `test_a_handled_signal_interrupts_a_blocking_call`) (on macOS 27, where PV steal time is offered, also a thread's own CPU time and `thread_info`: below) (any other one is a denial, below). Always: no program execution, no fork, no IP networking, no Mach service lookups (but the one starting a vmnet interface makes while the microVM is built: `test_vmnet_lookup_is_setups_only`), no IOKit, no sysctl writes, no file mapped executable, no `MAP_JIT`; after narrowing also no listening socket made, no sysctl reads, no signal action set (upstream's filters allow `rt_sigaction` then for SIGABRT only, which Seatbelt cannot tell apart, so this is stricter; a panic's `abort()` still ends by SIGABRT: `test_a_run_phase_sigaction_is_a_denial`, `test_the_other_ends_are_unchanged_without_a_denied_call`), `fcntl` commands only from its list, no change to a file's mode, owner, flags, times or extended attributes, driver ioctls only for the terminal's settings and a block device's sizes, and no anonymous mapping asking for `PROT_EXEC` (checked in the compatibility libc: macOS has no kernel rule for it, so a raw system call is not checked; `test_executable_mappings_are_denials`). A denied operation of any kind ends Firecracker inside the call, except a file outside what is allowed, which fails with an error as outside a chroot: every denying rule's action is `(with send-signal SIGKILL)`, which the kernel delivers before the call returns, so the call never returns to its thread and no signal mask, disposition or thread state can keep Firecracker running (`test_a_denied_call_never_returns_to_its_thread`, `test_an_ignored_or_replaced_sigsys_cannot_keep_a_denied_process_running`, `test_a_process_wide_sigsys_block_cannot_keep_a_denied_process_running`; macOS 27.2 here, and Seatbelt's action alone on macOS 15 and 26 in CI run 43497862443, `tools/macos/seatbelt-kill-probe.py`), as Linux skips the call and forces SIGSYS on that thread, whose handler then exits (kernel/seccomp.c `__seccomp_filter`, `SECCOMP_RET_TRAP`, the `default_action` of each of upstream's filters, resources/seccomp/{aarch64,x86_64}-unknown-linux-musl.json; the handler's `_exit`, vmm/src/signal_handler.rs). A number the kernel has no call for is checked as `SYS_invalid`, which no list has (XNU bsd/dev/arm/systemcalls.c `unix_syscall`), so it is a denial too (`test_an_unknown_syscall_number_is_a_denial`). The end itself differs: SIGKILL, with the sandbox's exit reason (namespace 25, `OS_REASON_SANDBOX`) and a crash report, where Linux exits 148 with upstream's log line and fault metric. Seatbelt has no action that traps the calling thread; a catchable signal goes to the process, and with SIGSYS, wick's end until 81072df, the denied call returned `EPERM` to a thread that ran on, denied whatever else it asked, for a median 0.74 to 1.9 ms and at most 14.8 ms before the exit (macOS 27.2 at b05cd23, load average 13 to 18), and code already running in Firecracker could keep it alive (SIGSYS ignored, or blocked). Firecracker's parent can tell this end from any other SIGKILL by its exit reason (docs/COMPATIBILITY.md, the denied-call row); the API process's denials end Firecracker as upstream's do, since Firecracker is that process's parent (below). Seatbelt skips the rule on the number of some system calls (`write`, `open`, `socket`, `ioctl`, ...) when a rule allows the operation they make, 92, 102 and 104 of them on macOS 15, 26 and 27; where an older major checks the number of one that 27 lets through, the run phase lists it, so every major behaves alike; each is tied to the rule that decides it, and 8 that nothing decides (`getpid`, `umask`, ...) are written down (docs/PORTING.md row 1; `test_unfiltered_syscalls_are_limited_by_their_rule`, `ext::sandbox` unit tests, `test_narrowing_is_one_way`, every `boot-test` stage, `tools/macos/sandbox-discovery.sh`) | **in place:** a process mitigation profile, each mitigation tied to the seccomp rule it stands for, in upstream's two phases: until the microVM is built (where Linux installs the VMM thread's filter) it sets what building takes — no child processes, no win32k, strict handle checks, extension points disabled, Microsoft-signed images only; then it narrows for good, adding no dynamic code and the image-load restrictions (no remote or low-label images, System32 first). A denied operation ends Firecracker with upstream's bad-syscall code where Windows reports it (an executable mapping, a handle the process does not hold), else fails closed (`ext::sandbox` unit tests: `test_win32k_policy`, `test_dynamic_code_policy`, `test_narrow_ends_the_setup_phase`, `test_denied_operation_exits_as_seccomp`, `test_denied_operations_fail_closed`; the run is found with `tools/windows/mitigation-audit.ps1`) |
| Jailer: chroot | upstream | **in place:** upstream's jailer; `chroot(2)`, entered by Firecracker right after the exec, and a Seatbelt file rule limited to the jail (`jailer-test jail`) | **in place:** upstream's jailer; the jail as a drive letter of its own with the current directory its root, and a protected directory ACL open to the jail's SID (`jailer-test.ps1 isolation`, `drives`) |
| Jailer: network namespace | upstream | Seatbelt denies IP networking to every Firecracker; `--netns <dir>` names the jail's network, a directory of endpoints the operator made, where Firecracker makes its network endpoints (each jail's are in a directory of its own there, `<dir>/<id>/`, which only that jail and the directory's owner or root reach, as a TAP is its owner's: `test_each_jail_has_a_network_directory_of_its_own`, `test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint`; an endpoint sends frames only to the switch's sockets, directly in `<dir>`: `test_a_jails_endpoint_takes_only_the_switch_as_a_peer`; two jails of one uid are kept apart by the profile alone, see below), and the sandbox lets a jail with a network reach Unix sockets only in its own directory there, directly in `<dir>` and in the jail (`test_jail_network_profile_limits_sockets`, `test_endpoint_in_network_directory`, `jailer-test netns`) | **in place:** `--netns <dir>` names the jail's network, a directory of endpoints the operator made, where Firecracker makes its network endpoints (in the jail's own directory in it, `<dir>\<id>`, which only that jail and the operator reach: no other jail can connect to its endpoints, delete them or take their names, as a TAP is its owner's on Linux, and a second jail of a running id is refused as busy; `test_the_network_directory_grants_no_jail`, `test_each_jail_has_a_network_directory_of_its_own`, `test_a_second_jail_of_one_id_is_refused_and_the_first_keeps_its_endpoint`: written, compiled and unit-tested on CI; `jailer-test.ps1 netns`, the elevated stage, and `jailer-test.ps1 netguest` passed with this layout in CI run 43442912128, 861d365, elevated), and the jail's copy of Firecracker gets no IP networking at all: Windows Filtering Platform block filters on its application id at every connect, bind, listen and accept layer, IPv4 and IPv6, in a session that ends with the jailer. Needs an elevated jailer (adding a filter is an administrator's right, as `setns` needs root); refused loudly without one. An AppContainer was not usable: WHP refuses to run inside one (`jailer-test.ps1 netns`, `refuse`) |
| Jailer: uid/gid | upstream | **in place:** dropped right after the chroot, checked that root cannot be regained (`jailer-test jail`, `test_enter_needs_root`) | **in place:** a restricted token below medium integrity, without the user's SID and with a random SID per jail: no access to the user's files, another jail, or other processes, and, since the jail's integrity level is above low, no access from a plain low-integrity process of the same user either (`jailer-test.ps1 isolation`, `low`); no privilege but traversal (`test_tokens_keep_only_traversal`): below medium integrity no privilege can be enabled, "Lock pages in memory" included, so a jailed Firecracker cannot map large pages itself; the jailer makes them for it, as sections no larger in all than `hugetlb.2MB.max` (`jailer-test.ps1 hugepages`, docs/PORTING.md row 10) |
| Jailer: PID namespace | upstream | in place in every jail: the sandbox keeps every other process out of Firecracker's reach (no process information, no signal); `--new-pid-ns` gives upstream's process tree and drops the signals a namespace's init does not get from outside; the pid is the host's (`test_no_other_process_in_reach`, `jailer-test pidns`) | **in place** in every jail: no process or thread outside the jail opens to Firecracker, a process snapshot shows it none, and it is not on the jailer's console (no console control events or typed input; the jailer relays the console); `--new-pid-ns` returns as upstream's jailer does. Whether a pid is in use still shows (`jailer-test.ps1 pidns`) |
| Jailer: cgroups (memory, CPU) | upstream | memory **in place** (jetsam limit, killed at the limit as by the OOM killer); CPU **in place** (`cpu.max` / `cpu.cfs_quota_us` → a kernel CPU limit on the whole VMM, throttled once it used its share of each second); `cpuset` naming every CPU and memory node accepted (no restriction), as is a limit macOS does not have set to no limit (`pids.max=max`, `memory.high=max`, ...); the freezer through upstream's files next to the jail, kept by a root supervisor per jail (below); other controllers, and those limits with a number, refused, each with its reason (`jailer-test limits`, `jailer-test memory`, `jailer-test cpu`, `jailer-test freeze`, `test_cpu_limit_holds`, `test_other_controllers_are_refused`, `test_no_limit_values_are_accepted`, `test_only_no_limit_is_accepted_of_a_limit_macos_lacks`) | CPU **in place** through a Job Object (CPU rate hard cap from Firecracker's start or a CPU weight); memory **not in place**: the Job Object's memory limit holds private memory only, and memory in sections escapes it (see below; `jailer-test.ps1 sections` fails); `cpuset.cpus` as the job's affinity; the freezer through upstream's files next to the jail, kept by the jailer, which freezes the job (below); other controllers refused with the reason (`jailer-test.ps1 limits`, `jailer-test.ps1 cpu`, `jailer-test.ps1 cpuset`, `jailer-test.ps1 weight`, `jailer-test.ps1 refuse`, `jailer-test.ps1 freeze`) |

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

Every planned mechanism above has been measured on its host with a probe
([`tools/windows/winprobe.c`](tools/windows/winprobe.c) on Windows); the [roadmap](docs/ROADMAP.md), milestone M5,
has the per-control details and results.

## Not at parity yet

Until these are done, **do not run untrusted multi-tenant workloads on macOS or Windows hosts.** On Linux, wick is
upstream Firecracker and its jailer.

- **Without the jailer, the VMM runs as the user who started it** on macOS and Windows: an escape from the VM and
  then the VMM lands as that user (files are then not limited, as on Linux without the jailer).
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
  sockets alone: keep nothing there but the switch's sockets (`test_each_jail_has_a_network_directory_of_its_own`).
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
- **Windows jailer: the jail reads what every process of the session may read.** On Linux the chroot leaves the
  host's files out of reach. A Windows jail is a drive letter of its own: every other path stays reachable, and only
  the jail's token confines it. Its restricting SIDs are the jail's own SID and four groups
  every process of the session has: Everyone, Users, Authenticated Users and Interactive
  (overlay/jailer/platform/windows/mod.rs, `RESTRICTING_SIDS`). A restricted token is granted only what both its
  enabled SIDs and its restricting SIDs are granted (Microsoft, CreateRestrictedToken), so a jailed Firecracker can
  read what those groups may read: the Windows directory, Program Files, and files under ProgramData,
  `C:\Users\Public` or a data volume, and HKLM registry keys, that grant one of them read. Its integrity level,
  below medium, keeps it from writing them, and the user's own files stay denied (`jailer-test.ps1 isolation`).
  Not done yet: ALL APPLICATION PACKAGES, what an AppContainer may read (the Windows directory and Program Files),
  in place of the four groups, once measured, since whether WHP and Winsock accept such a token is not known; then
  a less-privileged AppContainer for the API process, which needs no WHP.
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
- **Windows jailer: `memory.max` does not bound memory in sections.** The jailer sets `memory.max` as a Job Object
  memory limit, which charges private memory only. Sections (pagefile-backed, or of a file: wick's memfd is a
  temporary file's) are not charged to the job, and the jail's token does not stop a process making them: under
  `memory.max` of 32 MiB a jailed process stops after 30 MiB of private memory but maps and writes 256 MiB of
  each kind of section (`jailer-test.ps1 sections`, measured elevated on Windows Server 2022; with 4 GiB of
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
  `test_anonymous_shared_memory_is_charged_at_first_touch`, not yet run since it was made to run alone). A touched page so takes twice its size of host commit and once of memory.
  The userfaultfd restore's section is charged the same way: reserved at the registration, each page committed with
  its charge when the handler fills it, and a fill past `memory.max` fails with `ENOMEM`, as Linux's `UFFDIO_COPY`
  does when the memory cgroup refuses the page (`test_a_fill_past_the_job_limit_fails_with_enomem`, which passed in
  CI run 43534301411). A 2 MiB chunk discarded whole with `MADV_DONTNEED` (free page reporting; the section is one
  per chunk) gets a new, empty section, so its commit and charge go
  (`test_a_wholly_discarded_chunk_gives_its_section_commit_back`). A page discarded in a chunk not discarded whole
  (balloon inflation's scattered pages) keeps its section page committed (a SEC_RESERVE page cannot be decommitted)
  and its charge with it, so that what the jail is charged is never less than the host commit it holds
  (`test_registered_memory_is_charged_as_it_is_filled`; not yet run on Windows); the cost is the memory.max row's
  difference (such pages counted on top of live memory until their chunk goes), which reclaim at the limit is to
  close. Still not charged: memfds and
  sections made around wick.
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
  the token's construction; not measured for pipes); a pipe made with a DACL that grants everyone is opened. So a
  jail that can make pipes could, once the first reader has gone, take the log or metrics another jail of the same
  user wrote meanwhile (up to 64 KiB), if it knows the name. Run each jail's pipes under names the others cannot
  guess, or run tenants under different accounts.
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
  (`test_an_api_process_that_exits_148_is_no_denial`). In a jail the two share the jail's memory and CPU limits, so together they stay within
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
- **The WHP x2APIC partition's #GP exit (option E, AMD hosts; in the code, off in the product until
  `test_a_page_set_loses_no_requested_interrupt` is on record, so no product partition has it yet).** On one, every guest #GP, at any privilege level, leaves the
  hypervisor to the vCPU's run loop (`gp`), so a guest can make such exits at will (a ring-3 privileged
  instruction). The handler decodes at most 15 bytes from the exit context and reads at most three of the vCPU's own
  registers; it takes no lock another vCPU or the VMM's thread waits on, and neither allocates nor logs, so a storm
  of them costs that vCPU's thread, which runs under the jail's CPU limit like any guest work, as a guest's busy loop
  does. KVM intercepts every #GP the same way when `enable_vmware_backdoor` is set (Linux v6.1
  arch/x86/kvm/vmx/vmx.c 791, 5091-5103). The decode and the merge are unit-tested on every host (fuzz crate
  `whp_gp`); the storm's isolation (another vCPU's rate, the API's latency, the job's CPU accounting) is not
  measured yet, and nothing of it has run on Windows yet. Its LVT timer write in TSC-deadline mode is a get and a
  set of the vCPU's own APIC register page (WHP's register refuses that mode): an interrupt requested between them
  and lost would stall only this guest's device or IPI, never reach another VM or the host;
  `test_a_page_set_loses_no_requested_interrupt` shows whether one is kept (not yet run on Windows).
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
