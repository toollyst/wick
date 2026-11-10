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
| System call filter | per-thread seccomp-BPF (upstream) | **in place:** a Seatbelt profile, process-wide: no program execution, no fork, no IP networking, no Mach service lookups, no IOKit, no sysctl writes | **in place:** a process mitigation policy that blocks child-process creation; the full mitigation profile is planned |
| Jailer: chroot | upstream | planned: Seatbelt path rules limited to the jail directory | planned: AppContainer + jail directory ACL |
| Jailer: network namespace | upstream | Seatbelt already denies IP networking | planned: AppContainer without capabilities |
| Jailer: uid/gid | upstream | planned: setuid from a root jailer | planned: per-VM AppContainer SID |
| Jailer: cgroups (memory, CPU) | upstream | planned: jetsam limit, vCPU time quota | planned: Job Object limits |

The sandbox is installed where upstream installs its seccomp filters and keeps upstream's flags: on by default, off
with `--no-seccomp`. `--seccomp-filter FILE` is refused outside Linux, because a BPF filter cannot be enforced there;
wick never accepts a security flag it cannot honor. If the host sandbox cannot be installed, Firecracker fails to
start rather than running without it.

Every planned mechanism above has been measured on its host with a probe
([`tools/windows/winprobe.c`](tools/windows/winprobe.c) on Windows); the [roadmap](docs/ROADMAP.md), milestone M5,
has the per-control details and results.

## Not at parity yet

Until these are done, **do not run untrusted multi-tenant workloads on macOS or Windows hosts.** On Linux, wick is
upstream Firecracker and its jailer.

- **No jailer on macOS or Windows.** The VMM runs as the user who started it. The macOS sandbox restricts what the
  process can ask the kernel for, but not which files it can read and write (the operator picks guest images,
  snapshots and sockets at run time). An escape from the VM and then the VMM lands as that user.
- **Windows confinement is partial.** Today it blocks child processes only; AppContainer network and filesystem
  confinement and Job Object limits come with the jailer. The Windows build has also not yet run a guest on real
  hardware (roadmap M3).
- **No per-thread filters outside Linux.** Neither macOS nor Windows filters system calls per thread. Threads of a
  process share its address space, so the plan applies the union of upstream's filters process-wide and moves the
  API server, whose separate filter is a real boundary, into a process of its own.
- **wick's host-side code is young.** The compatibility crates and the macOS and Windows backends (the
  Hypervisor.framework and WHP run loops, the userfaultfd kernel side, the network backends) have not had the years
  of review and fuzzing upstream's code has had, and have not had a third-party audit.
- **Side channels** between VMs on the same host follow upstream's
  [production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
  guidance on Linux; the equivalent guidance for macOS and Windows hosts is not written yet.
