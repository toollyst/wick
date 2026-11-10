# wick

**Firecracker microVMs on Linux, macOS and Windows: the same binary, API and
config on every host.**

wick builds [Firecracker](https://github.com/firecracker-microvm/firecracker)
from upstream's source. Upstream stays a pinned submodule, changed only by a
small patch series; everything Linux-only underneath it gets a native
implementation with Linux's semantics:

| Host | Hypervisor | Guests |
| --- | --- | --- |
| Linux | KVM (upstream, unchanged) | x86_64, aarch64 |
| macOS 15+ on Apple silicon | Hypervisor.framework | aarch64 |
| Windows 10 (1803+) and 11 | Windows Hypervisor Platform | x86_64 |

Tools that drive Firecracker (its REST API over a Unix socket,
`--config-file`, the vsock UDS convention) work with wick as they are; the
binaries are still called `firecracker` and `jailer`.

## Status

- **Linux**: upstream Firecracker. The compatibility crates re-export the
  original crates, and the platform interfaces' Linux backends are upstream's
  own code (io_uring, TAP). CI runs upstream's unit tests (x86_64 with KVM,
  aarch64) and integration tests for plain upstream and for wick on the same
  machine and requires the same result test by test, and boots a guest with
  the musl release binary on KVM.
- **macOS**: boots and runs guests. Serial, API socket, virtio-blk (Sync and
  Async), vsock, virtio-net (vmnet or a Unix datagram endpoint), PCI with
  MSI-X, full and diff snapshots, userfaultfd-backed restore, vhost-user, and
  a Seatbelt sandbox in place of seccomp.
- **Windows**: the WHP backend and the POSIX layer are complete and the
  binary builds, but it has **not yet booted a guest on real hardware**.
  Treat it as a preview.

Security on macOS and Windows is not yet at Firecracker's Linux level: the
jailer's equivalents are in progress. See [SECURITY.md](SECURITY.md) and the
[roadmap](docs/ROADMAP.md).

## Build

```sh
git clone --recurse-submodules https://github.com/toollyst/wick
cd wick
tools/setup.sh                 # check out upstream and apply patches/
cd lib/firecracker
cargo build -p firecracker     # cargo runs in lib/firecracker
```

On macOS (Apple silicon, macOS 15 or later), build, sign with the
Hypervisor.framework entitlement and run in one step:

```sh
tools/macos/run.sh -- --api-sock /tmp/firecracker.socket
```

Then drive it exactly as upstream's
[getting started guide](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
describes, with an aarch64 guest kernel and rootfs.

For Windows, cross-compile from macOS or Linux with mingw-w64:

```sh
cd lib/firecracker
AWS_LC_SYS_NO_ASM=1 cargo build -p firecracker --target x86_64-pc-windows-gnu
```

## How it stays upstream

```text
lib/firecracker/   upstream Firecracker at patches/base (v1.18.0)
patches/           15 feature patches: about 1,000 changed lines in 62 upstream files, plus Cargo.lock
overlay/vmm/       new vmm modules (vmm::ext, vmm::platform), compiled into upstream's crate
crates/compat/     Linux-only dependencies on macOS and Windows (libc, kvm-ioctls, vmm-sys-util, ...)
crates/ext/        wick's own features, behind vmm::ext
crates/version/    the version the binaries report, <upstream> or <upstream>+wick.<N> (patches/base + patches/version)
tools/             setup, patch export/check, rebase, generators, Linux tests against upstream and boot test, macOS run/test/boot test, Windows boot test and probe, release
```

- Upstream code changes only through `patches/`, and every change carries a
  `wick:` comment (`git grep wick:` in lib/firecracker).
- The compatibility crates sit below the dependencies' own APIs:
  `kvm_ioctls::VcpuFd::run()` runs on Hypervisor.framework or WHP, `libc`
  gains `fallocate`, `memfd_create` and the userfaultfd kernel side, and
  `vmm-sys-util`'s eventfd and epoll work on kqueue or IOCP. On Linux each one
  re-exports the original crate.
- New upstream releases are followed with `tools/rebase.sh <tag>`.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains the design, and
[CONTRIBUTING.md](CONTRIBUTING.md) the workflow.

## License

Apache-2.0, like Firecracker. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
wick is not affiliated with Amazon Web Services or the Firecracker project.
