# Contributing to wick

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
`tools/macos/test.sh` for tests. Windows builds cross-compile from macOS or
Linux with mingw-w64:
`AWS_LC_SYS_NO_ASM=1 cargo build -p firecracker --target x86_64-pc-windows-gnu`.
Natively on Windows (MSVC), `cargo build -p firecracker` works as is; release
builds need [NASM](https://www.nasm.us/) on `PATH` for aws-lc-sys.
On a Windows machine with the Windows Hypervisor Platform feature,
`tools/windows/boot-test.ps1` boots upstream's x86_64 CI guest and checks boot,
serial I/O, SMP, the Async block engine and vsock; `tools/windows/winprobe.c`
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

wick's version is upstream's plus wick's number: `<upstream>-wick.<N>` (for
example `1.18.0-wick.1`, a valid semver string). The upstream part is
`patches/base`; N is the only thing in `patches/version`. The binaries report
it (`firecracker --version`, `GET /version`, and the jailer, snapshot-editor,
rebase-snap and seccompiler-bin), through `crates/version`, which reads both
files at build time. Format and compatibility versions stay upstream's: the
snapshot format (`--snapshot-version`), the API specification, and
cpu-template-helper, whose version is recorded in CPU fingerprints.

N starts at 1 for each upstream tag (`tools/rebase.sh` resets it). For the
next release on the same upstream, raise N in `patches/version` in a commit
of its own on `main` (`release: 1.18.0-wick.2`) and tag that commit with the
same version, `v1.18.0-wick.2`. Pushing a tag runs the release workflow,
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
