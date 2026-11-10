# Contributing to wick

Thanks for looking. wick runs on three operating systems and many machines, and nobody has all of them, so some of
the most useful contributions need no code at all:

- **Test runs on hardware we don't have.** A Windows PC with the Windows Hypervisor Platform
  (`tools/windows/boot-test.ps1`), Linux on aarch64 with KVM, a Mac with an M3 or M4. Open an issue with the result,
  pass or fail.
- **Bug reports.** Anything that works with upstream Firecracker on Linux and behaves differently with wick on
  another host is a bug, unless the [roadmap](docs/ROADMAP.md) says that feature is not there yet.
- **Fixes and features.** For anything bigger than a fix, open an issue first so we can agree on the shape. wick has
  firm rules about where code goes and how upstream may change (below), and it is cheaper to talk before code.

Security issues go through private reporting, not issues: see [SECURITY.md](SECURITY.md).
[docs/README.md](docs/README.md) is the map of the repository, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
explains the design.

## Getting started

```sh
git clone --recurse-submodules https://github.com/toollyst/wick
cd wick
tools/setup.sh                        # upstream at patches/base + the patch series
cd lib/firecracker
cargo build -p firecracker            # cargo always runs in lib/firecracker
```

macOS needs Apple silicon and macOS 15 or later (`MACOSX_DEPLOYMENT_TARGET=15.0`).
Binaries that create a VM must be signed with the Hypervisor.framework
entitlement: use `tools/macos/run.sh` to run Firecracker and
`tools/macos/test.sh` for tests. `tools/macos/boot-test.sh` runs scenario
tests against upstream's aarch64 CI guest (boot, SMP, block, vsock,
networking, snapshots, userfaultfd, PCI, vhost-user); run it before sending a
change to the macOS backends. Windows builds cross-compile from macOS or
Linux with mingw-w64:
`AWS_LC_SYS_NO_ASM=1 cargo build -p firecracker --target x86_64-pc-windows-gnu`.
Natively on Windows (MSVC), `cargo build -p firecracker` runs in a Visual
Studio developer shell (`vcvars64.bat`) with [NASM](https://www.nasm.us/) on
`PATH` for aws-lc-sys (debug builds can set `AWS_LC_SYS_NO_ASM=1` instead).
On a Windows machine with the Windows Hypervisor Platform feature,
`tools/windows/boot-test.ps1` boots upstream's x86_64 CI guest and checks boot,
serial I/O, SMP, Sync and Async block devices, vsock and virtio-net
(`tools/windows/README.md` has the steps); `tools/windows/winprobe.c`
measures the host mechanisms the sandbox and jailer backends use.

Editors: `.vscode/settings.json` points rust-analyzer at
`lib/firecracker/Cargo.toml`; other editors need the same.

## Where code goes

| Change | Where |
|---|---|
| A Linux-only dependency's API on another host | `crates/compat/<crate>` |
| A host facility behind an interface | `overlay/vmm/platform` |
| A wick feature | `crates/ext`, reached through `overlay/vmm/ext` |
| Anything in an upstream file | a patch (below) |

New code goes outside lib/firecracker. Upstream files change only through
patches, and a patch inserts a `cfg` block or a call rather than rewriting
upstream code. Never delete or disable an upstream file.

## Changing upstream code

The series is a set of commits on branch `wick` in lib/firecracker, one commit
per feature, exported to `patches/`.

1. Edit in lib/firecracker and commit there. Fold the change into the patch it
   belongs to (`git commit --fixup <commit>` and
   `git rebase -i --autosquash v1.18.0`), or add a commit for a new feature.
2. Mark every change with a `wick:` comment saying why, so `git grep wick:` in
   lib/firecracker finds them all.
3. Write the commit message as the patch header: what upstream lacks (Why),
   what the patch does (What), and how to see it work (Test).
4. `tools/patches.sh export`, then commit `patches/` in wick.
5. `tools/patches.sh check` must pass (CI runs it).

After pulling changes to `patches/`, run `tools/setup.sh` again. It refuses to
discard local commits on `wick` unless given `--force`.

## No pretending

- Never skip a feature the host lacks and report success. Implement the same
  semantics with the host's own facilities, or fail loudly when it is
  requested. An error is acceptable only where the hardware or OS physically
  cannot do it, and the roadmap's status table says so.
- Test-only shortcuts live in `cfg(test)` or in `tools/`.

## Commits

- One unit per commit: one compatibility crate, one wick feature, one patch.
- Subjects are `<area>: <what changed>`; wick's commits do not touch
  lib/firecracker except through `patches/` and the submodule pointer.
- New files start with `Copyright 2026 toollyst contributors.` and an
  `SPDX-License-Identifier`.

## Following upstream

wick follows upstream release tags. `patches/base` names the tag, and the
lib/firecracker pointer must be that tag's commit.

```sh
tools/rebase.sh v1.19.0               # rebase branch wick in lib/firecracker
# conflicts: resolve in lib/firecracker, git rebase --continue, then
tools/rebase.sh --finish v1.19.0
```

`Cargo.lock` conflicts are not resolved by hand: take upstream's, run
`cargo update -w` in lib/firecracker and amend the lockfile patch.
Compatibility crates re-export the original crate from the same git tag; when
upstream moves to a new version of a crate, the compatibility crate's tag and
version move with it.

## Releases

A release on an upstream base carries upstream's version: `v1.18.0` is wick
built on Firecracker v1.18.0. wick's own fix releases on the same base, if
there are any, are `v1.18.0+wick.1`, `v1.18.0+wick.2`, ...: semver build
metadata, so a fix release never sorts below the upstream release it fixes
(a pre-release such as `1.18.0-wick.1` would). The upstream part is
`patches/base`; the fix number is the only thing in `patches/version` (0 for
the release of the base). The binaries report the same string
(`firecracker --version`, `GET /version`, and the jailer, snapshot-editor,
rebase-snap and seccompiler-bin), through `crates/version`, which reads both
files at build time. Format and compatibility versions stay upstream's: the
snapshot format (`--snapshot-version`), the API specification, and
cpu-template-helper, whose version is recorded in CPU fingerprints.

The number is 0 after each new upstream base (`tools/rebase.sh` resets it).
For a fix release on the same upstream, raise it in `patches/version` in a
commit of its own on `main` (`release: 1.18.0+wick.1`) and tag that commit
with the same version, `v1.18.0+wick.1`. Pushing a tag runs the release workflow,
which refuses a tag that is not exactly `v` + the version from those two
files, then builds and packages the macOS binary
(`tools/package-release.sh`) and checks that it reports the tag. Hosted
runners cannot run Hypervisor.framework guests, so run the L3 scenarios on a
Mac before tagging.

## Tests

| Level | What | Where |
|---|---|---|
| L1 | upstream unit tests + compatibility crate tests | CI (three OSes), Docker |
| L2 | upstream integration tests that work on nested KVM | Linux with KVM |
| L2' | all of upstream's tests, including performance | a Linux machine, before a release |
| L3 | API-driven scenarios: boot and serial, vsock, block, shutdown | Linux CI, a Mac, a Windows PC |

- Linux results must match upstream's **by test name**. Upstream tests that
  share global state and only flake when run in parallel
  (`balloon::device::tests::test_hinting_*`,
  `vsock::unix::muxer::tests::test_vsock_basic_metrics`) are re-run with
  `--test-threads=1`.
- Upstream tests left out on purpose: `test_licenses.py::test_for_valid_licenses`
  (wick's copyright headers) and `tests/integration_tests/performance/`
  (baselines measured on AWS bare metal).

## Pull requests

- One change per pull request, with a test that fails without it: a unit test in the crate, an interface test in
  `platform::<iface>::tests` that runs against every backend, or a scenario in the boot tests.
- Say which hosts you built and tested on. A change to a macOS backend needs a `tools/macos/boot-test.sh` run; a
  change to a Windows backend that you could not run on a WHP machine should say so, and someone with one will.
- Run the checks CI runs: `tools/patches.sh check`, the build and clippy for your host, and the compatibility crates'
  tests (`.github/workflows/ci.yml` has the exact commands).

By contributing, you agree that your work is licensed under the project's license (Apache-2.0).
