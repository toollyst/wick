# wick documentation

| Read | When you want to |
| --- | --- |
| [getting-started.md](getting-started.md) | Boot your first microVM: build, guest images, config file, REST API, networking |
| [ROADMAP.md](ROADMAP.md) | See what works on each host, what is next, and what "done" means for each milestone |
| [../SECURITY.md](../SECURITY.md) | Know how each of Firecracker's controls is held on each host, and what is not at parity yet |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Understand the design: the layers, the compatibility crates, the POSIX layer on Windows |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Change wick: where code goes, the patch workflow, commits, tests and releases |
| This page | Find your way around the repository as a contributor |

For everything Firecracker itself does (the API, snapshots, vsock, metrics, the jailer's CLI), upstream's
[documentation](https://github.com/firecracker-microvm/firecracker/tree/main/docs) applies unchanged. These pages only
cover what wick adds or does differently.

The rules themselves live in code: doc comments, `wick:` comments in the patches, tests and `tools/patches.sh check`.
These pages explain the shape and point to the code. When the two disagree, the code is right, and the page is a bug.

## The repository

```text
lib/firecracker/          upstream Firecracker: a submodule at the tag in patches/base, plus branch `wick`
patches/                  the patch series: series, base, version and one .patch per feature
overlay/vmm/              new modules compiled into upstream's vmm crate
  ext/                    vmm::ext: the extension point and the host sandbox (sandbox.rs)
  platform/               vmm::platform: host interfaces (async_io, fs, net, vnet) and a backend per OS
    linux/  macos/  windows/
crates/
  compat/<crate>/         Linux-only dependencies, rebuilt for macOS and Windows with the same API
  ext/                    wick-ext: wick's features behind vmm::ext
  version/                wick-version: the version string every binary reports
tools/                    everything you run by hand or in CI (below)
  macos/                  run, test and boot-test on Apple silicon
  windows/                boot test and host capability probe for a Windows PC
  vhost-user-blk/         a vhost-user-blk backend used by the macOS boot test
docs/                     these pages
.github/workflows/        ci.yml (every push and pull request), release.yml (tags v*)
```

Cargo always runs in `lib/firecracker`. Upstream's workspace is the only workspace: its patched manifest lists
`crates/compat/*`, `crates/ext` and `crates/version` as members, so there is one `Cargo.lock` and one set of lints.
Editors need to know that too; `.vscode/settings.json` points rust-analyzer at `lib/firecracker/Cargo.toml`.

### The compatibility crates

Each one stands in for a crate (or the part of `std`) that upstream uses and that only works on Linux. On Linux it
re-exports the original crate from the same git tag; on macOS and Windows it implements the same API, with the same
semantics, on that host's facilities.

| Crate | Stands in for | macOS | Windows |
| --- | --- | --- | --- |
| `kvm-ioctls` | the KVM API | Hypervisor.framework (vCPUs, memory, GICv3, MSI frame, dirty tracking) | Windows Hypervisor Platform (partition, LAPIC, user-space IOAPIC/PIC/PIT) |
| `kvm-bindings` | KVM structures | the original | generated with the Linux x86_64 layout |
| `libc` | Linux-only libc | `fallocate`, `memfd_create`, the userfaultfd kernel side (`wick_uffd`), ... | the POSIX layer over Win32: fds as handles, mmap, sockets, signals (`wick_fd`) |
| `vmm-sys-util` | eventfd, epoll, timerfd, signals | pipes, kqueue, timer threads | IOCP, sections, waitable timers |
| `userfaultfd` | the userfaultfd API | on the userfaultfd kernel side in the compatibility `libc` | the API builds; creating a userfaultfd fails until it is implemented (roadmap) |
| `memfd` | memfd and seals | an unlinked POSIX shared memory object | an unnamed temporary file; size seals are sections |
| `os`, `std` | `std::os::{unix, fd}` | re-exported | the same traits and types on handles |
| `vm-memory`, `event-manager`, `micro-http`, `vhost` | rust-vmm crates | the original | upstream's source with mechanical rewrites, generated |

## Everyday commands

```sh
tools/setup.sh                          # after cloning and after pulling changes to patches/
cd lib/firecracker
cargo build -p firecracker              # build
cargo clippy -p vmm -p firecracker -p wick-ext --lib --bins --tests -- -D warnings
cd ../..

tools/macos/test.sh                     # upstream's vmm unit tests with Hypervisor.framework (macOS)
tools/macos/boot-test.sh                # scenario tests in a real guest (macOS), before any change to a macOS backend
tools/patches.sh export                 # after committing a change on branch `wick` in lib/firecracker
tools/patches.sh check                  # what CI checks about patches/
```

| Tool | What it does |
| --- | --- |
| [`tools/setup.sh`](../tools/setup.sh) | Checks out upstream at `patches/base` and applies the series as commits on branch `wick` (`--force` discards local commits) |
| [`tools/patches.sh`](../tools/patches.sh) | `export` writes `patches/` from branch `wick`; `check` verifies it matches, that every changed upstream file carries a `wick:` comment and that the submodule is at `patches/base` |
| [`tools/rebase.sh`](../tools/rebase.sh) | Moves the series to a new upstream tag (`--finish` after resolving conflicts) |
| [`tools/macos/run.sh`](../tools/macos/run.sh) | Builds, signs with the Hypervisor.framework entitlement and runs `firecracker` |
| [`tools/macos/test.sh`](../tools/macos/test.sh) | Runs unit tests with the entitlement (through [`sign-and-run.sh`](../tools/macos/sign-and-run.sh) as the cargo runner) |
| [`tools/macos/boot-test.sh`](../tools/macos/boot-test.sh) | Scenario tests against upstream's aarch64 CI guest: boot, SMP, block, vsock, net, vmnet, snapshots, diff, uffd, PCI, vhost-user |
| [`tools/windows/boot-test.ps1`](../tools/windows/boot-test.ps1) | Boots upstream's x86_64 CI guest on WHP: boot, serial, SMP, Async block, vsock |
| [`tools/windows/winprobe.c`](../tools/windows/winprobe.c) | Measures the Windows mechanisms the sandbox and jailer backends use |
| [`tools/gen-windows-sources.sh`](../tools/gen-windows-sources.sh) | Generates the Windows builds of the rust-vmm crates (`--check` in CI) |
| [`tools/gen-kvm-bindings-windows.sh`](../tools/gen-kvm-bindings-windows.sh) | Generates `kvm-bindings` with the Linux x86_64 layout for Windows (`--check` in CI) |
| [`tools/package-release.sh`](../tools/package-release.sh) | Packages a macOS release in upstream's release layout |

## Where the rules live

| Rule | Source of truth |
| --- | --- |
| Which upstream release wick is built on | [`patches/base`](../patches/base), and the submodule pointer, which must match |
| The order of the patches | [`patches/series`](../patches/series), written by `tools/patches.sh export` |
| What a patch may do (every changed upstream file marked `wick:`; `list` shows the files the series touches) | `tools/patches.sh check` |
| The version every binary reports | [`crates/version`](../crates/version), from `patches/base` and `patches/version` |
| The semantics a host backend must keep | the interface's doc comment in [`overlay/vmm/platform/`](../overlay/vmm/platform/) (for example `net.rs`) and its `tests` module, run against every backend |
| What the host sandbox allows, per host and per flag | [`overlay/vmm/ext/sandbox.rs`](../overlay/vmm/ext/sandbox.rs) |
| How a wick feature is reached (`PUT /extensions/{name}`, the config file's `extensions`) | [`overlay/vmm/ext/mod.rs`](../overlay/vmm/ext/mod.rs), [`crates/ext`](../crates/ext/src/lib.rs) |
| How a Linux facility is rebuilt on Windows | the comments of each `crates/compat/*/src/windows*` module |
| What CI runs on each OS | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
