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
- `wick-<tag>-<os>-<arch>.cdx.json`: the SBOM (CycloneDX 1.5), every crate the binary is built from, with the version
  and the checksum or git commit `Cargo.lock` pins.
- Attestations, signed through Sigstore by the workflow run that built the release and recorded for this repository:
  SLSA build provenance and the SBOM, both for the archive and for the `firecracker` binary in it.

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

The same command works on the extracted binary (`release-v1.18.0-darwin-aarch64/firecracker-v1.18.0-darwin-aarch64`).
`--predicate-type https://cyclonedx.org/bom` checks the SBOM attestation instead of the provenance, and
`--format json` prints what was verified, including the commit the release was built from.

The macOS binary carries only an ad-hoc code signature (it is not signed with an Apple Developer ID); the attestation
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
| System call filter | per-thread seccomp-BPF (upstream) | **in place:** a Seatbelt profile, process-wide, in upstream's two phases: until the microVM is built (when Linux installs the VMM thread's filter) it allows what building takes; then it narrows for good, as no extension can be issued, taken or released any more, to 102 system calls, 15 Mach traps and 7 kernel MIG routines, each tied to the Linux rule it stands for (any other one raises SIGSYS and Firecracker exits with upstream's bad-syscall code, as on a seccomp trap). Always: no program execution, no fork, no IP networking, no Mach service lookups (but the one starting a vmnet interface makes while the microVM is built: `test_vmnet_lookup_is_setups_only`), no IOKit, no sysctl writes, no file mapped executable, no `MAP_JIT`; after narrowing also no listening socket made, no sysctl reads, `fcntl` commands only from its list, no change to a file's mode, owner, flags, times or extended attributes, driver ioctls only for the terminal's settings and a block device's sizes, and no anonymous mapping asking for `PROT_EXEC` (checked in the compatibility libc: macOS has no kernel rule for it, so a raw system call is not checked; `test_executable_mappings_raise_sigsys`). A denied operation of any kind raises SIGSYS, except a file outside what is allowed, which fails with an error as outside a chroot; Seatbelt signals the process, not the thread that made the call, so the denied call returns `EPERM` and its thread runs on, denied whatever else it asks, until Firecracker has exited 148 (about 1 ms, at most 12 ms under load); Linux skips the call and forces SIGSYS on that thread, whose handler then exits (kernel/seccomp.c `__seccomp_filter`, `SECCOMP_RET_TRAP`, the `default_action` of each of upstream's filters, resources/seccomp/{aarch64,x86_64}-unknown-linux-musl.json; the handler's `_exit`, vmm/src/signal_handler.rs). Upstream's handler runs on a thread of its own, so that it never waits on a lock the interrupted thread holds, and within a deadline; two cases that need code already running in Firecracker stay different: SIGSYS ignored, or blocked by a thread that then calls a number the kernel has no call for (docs/PORTING.md row 3, `test_sigsys_does_not_wait_on_the_metrics_lock`, `test_sigsys_exits_by_its_deadline`). Seatbelt skips the rule on the number of some system calls (`write`, `open`, `socket`, `ioctl`, ...) when a rule allows the operation they make, 92, 102 and 104 of them on macOS 15, 26 and 27; where an older major checks the number of one that 27 lets through, the run phase lists it, so every major behaves alike; each is tied to the rule that decides it, and 8 that nothing decides (`getpid`, `umask`, ...) are written down (docs/PORTING.md row 1; `test_unfiltered_syscalls_are_limited_by_their_rule`, `ext::sandbox` unit tests, `test_narrowing_is_one_way`, every `boot-test` stage, `tools/macos/sandbox-discovery.sh`) | **in place:** a process mitigation profile, each mitigation tied to the seccomp rule it stands for, in upstream's two phases: until the microVM is built (where Linux installs the VMM thread's filter) it sets what building takes — no child processes, no win32k, strict handle checks, extension points disabled, Microsoft-signed images only; then it narrows for good, adding no dynamic code and the image-load restrictions (no remote or low-label images, System32 first). A denied operation ends Firecracker with upstream's bad-syscall code where Windows reports it (an executable mapping, a handle the process does not hold), else fails closed (`ext::sandbox` unit tests: `test_win32k_policy`, `test_dynamic_code_policy`, `test_narrow_ends_the_setup_phase`, `test_denied_operation_exits_as_seccomp`, `test_denied_operations_fail_closed`; the run is found with `tools/windows/mitigation-audit.ps1`) |
| Jailer: chroot | upstream | **in place:** upstream's jailer; `chroot(2)`, entered by Firecracker right after the exec, and a Seatbelt file rule limited to the jail (`jailer-test jail`) | **in place:** upstream's jailer; the jail as a drive letter of its own with the current directory its root, and a protected directory ACL open to the jail's SID (`jailer-test.ps1 isolation`, `drives`) |
| Jailer: network namespace | upstream | Seatbelt denies IP networking to every Firecracker; `--netns <dir>` names the jail's network, a directory of endpoints the operator made, where Firecracker makes its network endpoints (the jail's uid granted on it: jails given one directory share a network, a jail given its own reaches no other's), and the sandbox lets a jail with a network reach Unix sockets only there and in the jail (`test_jail_network_profile_limits_sockets`, `test_endpoint_in_network_directory`, `jailer-test netns`) | **in place:** `--netns <dir>` names the jail's network, a directory of endpoints the operator made, where Firecracker makes its network endpoints (the jail's SID granted on it: jails given one directory share a network, a jail given its own reaches no other's), and the jail's copy of Firecracker gets no IP networking at all: Windows Filtering Platform block filters on its application id at every connect, bind, listen and accept layer, IPv4 and IPv6, in a session that ends with the jailer. Needs an elevated jailer (adding a filter is an administrator's right, as `setns` needs root); refused loudly without one. An AppContainer was not usable: WHP refuses to run inside one (`jailer-test.ps1 netns`, `refuse`) |
| Jailer: uid/gid | upstream | **in place:** dropped right after the chroot, checked that root cannot be regained (`jailer-test jail`, `test_enter_needs_root`) | **in place:** a restricted token below medium integrity, without the user's SID and with a random SID per jail: no access to the user's files, another jail, or other processes, and, since the jail's integrity level is above low, no access from a plain low-integrity process of the same user either (`jailer-test.ps1 isolation`, `low`); no privilege but traversal (`test_tokens_keep_only_traversal`): below medium integrity no privilege can be enabled, "Lock pages in memory" included, so a jailed Firecracker cannot map large pages itself; the jailer makes them for it, as sections no larger in all than `hugetlb.2MB.max` (`jailer-test.ps1 hugepages`, docs/PORTING.md row 10) |
| Jailer: PID namespace | upstream | in place in every jail: the sandbox keeps every other process out of Firecracker's reach (no process information, no signal); `--new-pid-ns` gives upstream's process tree and drops the signals a namespace's init does not get from outside; the pid is the host's (`test_no_other_process_in_reach`, `jailer-test pidns`) | **in place** in every jail: no process or thread outside the jail opens to Firecracker, a process snapshot shows it none, and it is not on the jailer's console (no console control events or typed input; the jailer relays the console); `--new-pid-ns` returns as upstream's jailer does. Whether a pid is in use still shows (`jailer-test.ps1 pidns`) |
| Jailer: cgroups (memory, CPU) | upstream | memory **in place** (jetsam limit, killed at the limit as by the OOM killer); CPU **in place** (`cpu.max` / `cpu.cfs_quota_us` → a kernel CPU limit on the whole VMM, throttled once it used its share of each second); `cpuset` naming every CPU and memory node accepted (no restriction); the freezer through upstream's files next to the jail, kept by a root supervisor per jail (below); other controllers refused, each with its reason (`jailer-test limits`, `jailer-test memory`, `jailer-test cpu`, `jailer-test freeze`, `test_cpu_limit_holds`, `test_other_controllers_are_refused`) | CPU **in place** through a Job Object (CPU rate hard cap from Firecracker's start or a CPU weight); memory **not in place**: the Job Object's memory limit holds private memory only, and memory in sections escapes it (see below; `jailer-test.ps1 sections` fails); `cpuset.cpus` as the job's affinity; the freezer through upstream's files next to the jail, kept by the jailer, which freezes the job (below); other controllers refused with the reason (`jailer-test.ps1 limits`, `jailer-test.ps1 cpu`, `jailer-test.ps1 cpuset`, `jailer-test.ps1 weight`, `jailer-test.ps1 refuse`, `jailer-test.ps1 freeze`) |

The sandbox is installed where upstream installs its seccomp filters and keeps upstream's flags: on by default, off
with `--no-seccomp`. On macOS a process may lift its own CPU limit and the allow-list is what denies that, so a
jailed Firecracker with a CPU limit refuses `--no-seccomp`. `--seccomp-filter FILE` is refused outside Linux, because a BPF filter cannot be enforced there;
wick never accepts a security flag it cannot honor. If the host sandbox cannot be installed, Firecracker fails to
start rather than running without it.

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
  the virtualization entitlement (`vmnet_network_create`), and have not yet been run in a jail (`jailer-test vmnet`
  and `vmnet-guest`, written, need root). Firecracker starts as root and enters the jail before anything else
  runs (dyld cannot start a program inside a chroot), from a root-owned copy of the binary outside the jail.
- **macOS jailer: a root supervisor per jail, for the freezer.** macOS has no cgroup freezer, so every jail gets a
  supervisor: a fork of the jailer made just before the exec, which stays root (`pid_suspend` needs root), in a
  session of its own, chrooted to `/var/empty`, with only its standard descriptors (standard error is
  Firecracker's), the jail's directory and a pipe to the jailer. It reads one file that only root can write, by
  name in that directory: no link followed, only a regular, root-owned file with one link that root alone can
  write, at most 64 bytes, its content driving no allocation. It writes `cgroup.events` and suspends and resumes
  the jail's processes, known by pid and start time; it execs nothing and reads no environment. The jail cannot
  reach it: it is outside the chroot and root's, and Firecracker's sandbox allows signals to itself only. It ends
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
- **Windows jailer: `memory.max` does not bound memory in sections.** The jailer sets `memory.max` as a Job Object
  memory limit, which charges private memory only. Sections (pagefile-backed, or of a file: wick's memfd is a
  temporary file's) are not charged to the job, and the jail's token does not stop a process making them: under
  `memory.max` of 32 MiB a jailed process stops after 30 MiB of private memory but maps and writes 256 MiB of
  each kind of section (`jailer-test.ps1 sections`, measured elevated on Windows Server 2022; with 4 GiB of
  sections the host's commit grew by 4.1 GiB while the job's peak stayed at 9 MiB). A compromised jailed
  Firecracker can so take host memory past its limit, and guest memory backed by a memfd (with vhost-user
  devices) is not charged either.
- **Windows jailer: no limit on the number of handles.** Upstream's jailer limits Firecracker to 2048 descriptors
  by default (`RLIMIT_NOFILE`). Windows has no per-process handle limit to set: a process's pool quota is accepted
  and ignored, and a Job Object has no handle limit and its memory limit does not count handles (measured: 300,000
  handles under a 32 MiB job memory limit; `jailer-test.ps1 nofile` checks 100,000). Nothing bounds the handles of
  a compromised jailed Firecracker, or the kernel memory they take, short of Windows' fixed per-process maximum
  (2^24 handles, documented, not measured). The jailer refuses `--resource-limit no-file=` and says at its start,
  on stderr, that upstream's default is not enforced.
- **No per-thread filters outside Linux.** Neither macOS nor Windows filters system calls per thread. Threads of a
  process share its address space, so the union of upstream's filters applies process-wide, and the API server,
  whose separate filter is a real boundary, moves into a process of its own. On macOS that is in place: the API
  socket's HTTP server and upstream's request parsing run in a process sandboxed as upstream's `api` filter (its
  system calls only, no files, no shared memory, no executable mappings), and Firecracker's API thread handles the
  requests it passes on with upstream's code; either process's end ends the other (`test_api_profile_*`,
  `boot-test api-process`). A call the API process's sandbox denies ends Firecracker with the bad-syscall code,
  its log line and metrics, as the API thread's trapped call does on Linux: the API process says so over the link,
  or Firecracker, its parent, reads its exit status
  (`test_a_denied_call_in_the_api_process_ends_firecracker_as_its_own`,
  `test_an_api_process_that_exits_148_ends_firecracker_as_its_own`). A compromised API process that says so
  falsely can do no more than end Firecracker, which it can do anyway by ending the link. In a jail the two share the jail's memory and CPU limits, so together they stay within
  them (`test_limits_are_shared_with_the_api_process`; the jailer-test stage needs root). On Windows the same is
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
- **Side channels** between VMs on the same host follow upstream's
  [production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
  guidance on Linux; the equivalent guidance for macOS and Windows hosts is not written yet.
