<h1 align="center">wick</h1>

<p align="center">
  <b>Firecracker microVMs on Linux, macOS and Windows.</b><br>
  The same binary, the same REST API and the same config file on every host, built from upstream's own source.
</p>

<p align="center">
  <a href="https://github.com/toollyst/wick/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/toollyst/wick/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/firecracker-microvm/firecracker/releases/tag/v1.18.0"><img alt="Upstream: Firecracker v1.18.0" src="https://img.shields.io/badge/upstream-Firecracker%20v1.18.0-ff9900"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Hosts: Linux, macOS, Windows" src="https://img.shields.io/badge/hosts-Linux%20%C2%B7%20macOS%20%C2%B7%20Windows-lightgrey">
</p>

> [!IMPORTANT]
> **macOS works end to end; Windows is a preview.** On Apple silicon, wick boots upstream's own CI guests and passes
> scenario tests for SMP, block, vsock, networking, snapshots, userfaultfd, PCI and vhost-user. The Windows build is
> complete but has not yet booted a guest on real hardware. On macOS, upstream's jailer runs with macOS backends
> (chroot, uid/gid, the memory cgroup); on Windows it is not available yet. Read [SECURITY.md](SECURITY.md) before
> running untrusted multi-tenant workloads on either.

```sh
git clone --recurse-submodules https://github.com/toollyst/wick && cd wick
tools/setup.sh                                   # upstream v1.18.0 + wick's patch series
tools/macos/run.sh --release -- --api-sock /tmp/firecracker.socket
```

That is upstream Firecracker's API socket, now on a Mac. Everything in upstream's
[getting started guide](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md) works
from here: `curl --unix-socket`, `--config-file`, snapshots, the vsock UDS convention. The
[first microVM guide](docs/getting-started.md) takes you from a fresh clone to a Linux shell in a few minutes.

## Why wick

[Firecracker](https://firecracker-microvm.github.io/) is the microVM monitor behind AWS Lambda and Fargate: a minimal
device model, boot in milliseconds, snapshots, and a small REST API that a whole ecosystem of tools speaks. It only
runs on Linux with KVM. If you build on Firecracker, your laptop needs a Linux VM, and Windows users are left out.

wick removes that limit without forking Firecracker in the usual sense:

- **Upstream stays upstream.** `lib/firecracker` is the official repository at a release tag. wick changes it
  through 15 small feature patches (about 1,000 lines in 63 files), each marked with a `wick:` comment. Everything
  else is new code outside the submodule.
- **Same API, same meaning.** Tools that drive Firecracker work unchanged: the binary is still called `firecracker`,
  and the API, the config file, the snapshot format and the vsock convention mean the same on all three hosts.
- **No pretending.** When a host lacks a Linux facility, wick implements its semantics with the host's own facilities
  instead of skipping it: io_uring becomes worker-thread queues, TAP becomes vmnet, the kernel side of userfaultfd is
  rebuilt on `PROT_NONE` and stage-2 faults. Where a host truly cannot do something, wick fails loudly and the
  [roadmap](docs/ROADMAP.md) says so.
- **Security is not downgraded.** The goal is Firecracker's isolation on every host, with each Linux control mapped
  to a native mechanism: Seatbelt and AppContainer for seccomp and chroot, jetsam limits and Job Objects for cgroups.
  [SECURITY.md](SECURITY.md) lists every control and where it stands.

## Hosts

| Host | Hypervisor | Guests | Status |
| --- | --- | --- | --- |
| Linux x86_64, aarch64 | KVM | x86_64, aarch64 | **Upstream Firecracker** from the same source: the compatibility crates re-export the original crates, and the Linux backends are upstream's code. CI runs upstream's unit and integration tests on plain upstream and on wick, on the same machine, and requires the same result test by test |
| macOS 15+ on Apple silicon | Hypervisor.framework | aarch64 | **Works.** Checked end to end against upstream's CI guest by [`tools/macos/boot-test.sh`](tools/macos/boot-test.sh) |
| Windows 10 (1803+) and 11, x86_64 | Windows Hypervisor Platform | x86_64 | **Preview.** Builds and links, and its POSIX layer is tested natively in CI; first boot on real hardware pending |

### What works on macOS

| Feature | How |
| --- | --- |
| Boot, serial console, API socket, `--config-file` | Upstream's code on Hypervisor.framework, GICv3 through `hv_gic_*` |
| SMP | 1 and 2 vCPUs, work runs on each, the guest clock agrees between them |
| virtio-blk, Sync and Async engines | Async keeps io_uring's submission/completion model on worker threads, `F_FULLFSYNC` |
| vsock | Host → guest `CONNECT`, guest → host `<uds>_<port>`, over MMIO and PCI |
| virtio-net | vmnet (`vmnet-shared`, `vmnet-host`, `vmnet-br-<if>`) or a Unix datagram endpoint, with TUN's checksum, TSO and UFO in user space |
| PCI with MSI-X | `--enable-pci`, through a GICv2m MSI frame (Apple's GIC has no ITS) |
| Snapshots | Full and diff, restore in another process, `snapshot-editor rebase`, with PCI |
| userfaultfd (`Uffd` memory backend) | The kernel side of userfaultfd, rebuilt in user space |
| vhost-user | A vhost-user-blk backend in another process |
| Host sandbox | A Seatbelt profile in place of seccomp-BPF |

The full feature × host matrix is at the top of the [roadmap](docs/ROADMAP.md).

## Get started

You need Rust (cargo picks the toolchain pinned by upstream) and git.

**macOS** (Apple silicon, macOS 15 or later). Binaries that create a VM need the Hypervisor.framework entitlement;
`tools/macos/run.sh` builds, signs (ad hoc, enough to run locally) and runs in one step:

```sh
tools/setup.sh
tools/macos/run.sh --release -- --api-sock /tmp/firecracker.socket
```

**Linux.** This is upstream Firecracker; build it the usual way:

```sh
tools/setup.sh
cd lib/firecracker && cargo build -p firecracker --release
```

**Windows** (preview). Build natively with MSVC (release builds need [NASM](https://www.nasm.us/) on `PATH`), or
cross-compile from macOS or Linux with mingw-w64:

```sh
tools/setup.sh
cd lib/firecracker
AWS_LC_SYS_NO_ASM=1 cargo build -p firecracker --target x86_64-pc-windows-gnu
```

Every CI run on `main` uploads a natively built `firecracker.exe` as a workflow artifact, together with
[`tools/windows/boot-test.ps1`](tools/windows/boot-test.ps1), which boots upstream's x86_64 CI guest on a PC with
the *Windows Hypervisor Platform* feature turned on. If you have one, a run of it is the most useful contribution
right now.

Then follow [docs/getting-started.md](docs/getting-started.md) to boot your first microVM: a guest kernel and rootfs
from upstream's CI, a config file, and a shell.

## How it stays upstream

```text
lib/firecracker/   upstream Firecracker, a submodule pinned at patches/base (v1.18.0)
patches/           the feature patches applied to it, one per feature
overlay/vmm/       new vmm modules (vmm::platform, vmm::ext), compiled into upstream's crate
crates/compat/     Linux-only dependencies on macOS and Windows (libc, kvm-ioctls, vmm-sys-util, ...)
crates/ext/        wick's own features, behind vmm::ext
crates/version/    the version the binaries report
tools/             setup, patch export and check, rebase, generators, Linux tests against upstream, boot tests, release
```

```text
firecracker, jailer, vmm          upstream source + patches/
   ├─ vmm::platform               host interfaces with Linux semantics, one backend per OS
   │    linux/ = upstream's code   macos/ = Hypervisor.framework, kqueue, vmnet   windows/ = WHP, IOCP, Win32
   ├─ vmm::ext ──▶ wick-ext       wick's own features, behind one extension point
   └─ [patch.crates-io]           kvm-ioctls, libc, vmm-sys-util, userfaultfd, vm-memory, ...
                                  Linux: the original crate, re-exported unchanged
                                  macOS / Windows: the same API on the host's facilities
```

- **Below the API, not around it.** `kvm_ioctls::VcpuFd::run()` runs on Hypervisor.framework or WHP. `libc` gains
  `fallocate`, `memfd_create` and the userfaultfd kernel side. `vmm-sys-util`'s eventfd and epoll work on kqueue or
  IOCP. Upstream code above them does not know the difference.
- **Every upstream change is visible.** `git grep wick:` in `lib/firecracker` lists them all, and
  `tools/patches.sh check` (run in CI) enforces the patch rules.
- **New releases are a rebase.** `tools/rebase.sh v1.19.0` moves the series onto a new upstream tag.
- **Versions say what you get.** A release carries upstream's version (`v1.18.0` is wick on Firecracker v1.18.0);
  wick's own fixes on the same base are `v1.18.0+wick.1`, `+wick.2`, and so on, which never sort below upstream.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains the design, including the POSIX layer that lets upstream's
`RawFd`, epoll, eventfd and `SCM_RIGHTS` code run on Windows.

## Built on wick

- [**sbx**](https://github.com/toollyst/sandbox) runs any Docker image in its own microVM, with a Docker-style CLI and
  an MCP server for AI agents. On macOS, its Firecracker executor is wick.

Building something on wick? Open a pull request to add it here.

## Roadmap

The short version; the [full roadmap](docs/ROADMAP.md) has the status of every row.

- [x] Upstream as a submodule plus a checked patch series, rebase tooling, CI on three OSes
- [x] macOS: devices, snapshots, userfaultfd, PCI, vhost-user, Seatbelt sandbox, checked end to end
- [x] Windows: WHP backend and the POSIX layer, native CI
- [ ] Windows: first boot on real hardware, then snapshots and PCI
- [ ] Security parity: the upstream `jailer` CLI with native backends (macOS: chroot, uid/gid, memory limit in
  place; CPU limits and Windows next)
- [ ] Images everywhere: x86_64 images on Apple silicon (FEX-Emu with hardware TSO), arm64 images on Windows
- [ ] Desktop devices: user-mode networking, virtio-fs
- [ ] Distribution: release binaries, Homebrew, automatic rebase attempts on new upstream tags

## FAQ

<details>
<summary><b>Is this a fork of Firecracker?</b></summary>

Not in the usual sense. Upstream lives unmodified in a submodule at a release tag, and wick applies a small patch
series on top: about 1,000 changed lines, most of them a `cfg` block or a call into an interface. Everything else is
new code in its own crates. Following a new upstream release is a rebase of that series, not a merge of two diverged
trees.

</details>

<details>
<summary><b>Do my Firecracker tools work with it?</b></summary>

They should, unchanged: the binary is still `firecracker`, the REST API over a Unix socket is the same, and so are
`--config-file`, the snapshot format and the vsock UDS convention. Host-specific values are the exception: a network
interface on macOS is a vmnet mode or a Unix socket endpoint instead of a TAP device. If something that works on
Linux behaves differently on macOS, that is a bug; please report it.

</details>

<details>
<summary><b>Is it as secure as Firecracker on Linux?</b></summary>

That is the goal, and it is not negotiable: every control Firecracker has on Linux gets a native equivalent.
Hardware virtualization and the minimal device model are the same on every host, and the VMM process is already
confined by Seatbelt on macOS and by process mitigation policies on Windows. On macOS, upstream's jailer runs with
native backends for chroot, uid/gid and the memory cgroup; CPU limits there and the Windows jailer are in
progress. [SECURITY.md](SECURITY.md) lists each control, per host, with what is
done and what is not.

</details>

<details>
<summary><b>Can I run x86_64 guests on an Apple silicon Mac?</b></summary>

Not yet. The guest kernel always runs on the host's architecture with hardware virtualization. Running x86_64 user
space inside an arm64 guest, through FEX-Emu with Apple's hardware TSO, is planned (see "Images" in the
[roadmap](docs/ROADMAP.md)).

</details>

<details>
<summary><b>Will this be merged into upstream Firecracker?</b></summary>

That is up to the Firecracker maintainers. wick is built so that it never has to be: the patch series stays small,
and every change is marked and explained in its patch header.

</details>

## Contributing

Bug reports, test runs on hardware we don't have (Windows PCs with WHP, Linux aarch64 with KVM) and fixes are all
welcome. [CONTRIBUTING.md](CONTRIBUTING.md) has the workflow, and [docs/README.md](docs/README.md) is the map of
the code. Please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.

## License

Apache-2.0, like Firecracker. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

wick is an independent project, not affiliated with or endorsed by Amazon Web Services or the Firecracker project.
"Firecracker" is used here to name the upstream software that wick builds.
