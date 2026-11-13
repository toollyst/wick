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
networking, snapshots, userfaultfd, PCI, vhost-user, the devices, the command
line, memory hotplug and more); run it before sending a
change to the macOS backends. `tools/macos/jailer-test.sh` (run it as yourself: it asks for sudo, and refuses to start under it)
starts Firecracker through the jailer and checks the jail from outside; run it
before a change to the jailer's macOS backend or the Seatbelt profile. The macOS sandbox
allows only the system calls in `SYSCALLS` (overlay/vmm/ext/sandbox.rs), as
upstream's seccomp filters do on Linux: a change that makes Firecracker call
another one exits with code 148 under boot-test until the call is added there,
with the reason in the commit. Windows builds cross-compile from macOS or
Linux with mingw-w64:
`AWS_LC_SYS_NO_ASM=1 cargo build -p firecracker --target x86_64-pc-windows-gnu`.
Natively on Windows (MSVC), `cargo build -p firecracker` runs in a Visual
Studio developer shell (`vcvars64.bat`) with [NASM](https://www.nasm.us/) on
`PATH` for aws-lc-sys (debug builds can set `AWS_LC_SYS_NO_ASM=1` instead).
On a Windows machine with the Windows Hypervisor Platform feature,
`tools/windows/boot-test.ps1` boots upstream's x86_64 CI guest and runs the
macOS boot test's stages (`tools/windows/README.md` has the steps), and
`tools/windows/jailer-test.ps1` the jailer's; `tools/windows/winprobe.c`
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
- A table cell in README.md, SECURITY.md, docs/ROADMAP.md or docs/PORTING.md that says a
  control is "in place", "verified" or "measured" names, in backticks, the
  test that checks it (`jailer-test cpu`, `test_sandbox_restricts_child`).
  `tools/check-claims.py` enforces it on CI, and also that every
  `test_...` and every scenario stage a document names exists: a stage
  (`boot-test snapshot`, `jailer-test.ps1 nofile`) must be in that script's
  own stage table, so renaming a stage fails CI until the documents follow.
  A probe that once showed something is not a test; the claim waits until
  the product does it and a test in the repository shows it.
- A number in a doc says how it was measured. On a loaded machine, measure
  against a control run at the same time, or state only bounds the kernel
  reports back (a limit read back, CPU time used), never wall-clock alone.
- Find the cause before fixing a failure. Reproduce it, and fix what the
  reproduction shows, with a test that fails without the fix. A retry, a
  longer timeout or a skipped check added without a known cause hides the
  bug and is not accepted.

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

## Dependencies

CI checks the dependencies on every push and weekly, and the release workflow
before it builds. Run the same checks locally (they need the network):

```sh
cargo install --locked cargo-deny --version 0.19.0   # upstream's version, see below
tools/check-dependencies.sh
```

They cover `lib/firecracker/Cargo.lock` (with wick's patches) and
`tools/vhost-user-blk/Cargo.lock`, for every target:

- cargo-deny with upstream's own policy (`lib/firecracker/deny.toml`), as
  upstream runs it, and with wick's (`tools/deny.toml`, and
  `tools/vhost-user-blk/deny.toml` for the test backend), warnings as errors:
  RustSec advisories (vulnerable, unmaintained, unsound, yanked crates);
  licenses from upstream's list, all compatible with Apache-2.0 (MIT,
  Apache-2.0, BSD-3-Clause, 0BSD, ISC, Unicode-3.0); upstream's banned
  crates; no crate in two versions unless upstream's lockfile has both; and
  sources: crates.io and the git repositories listed in `tools/deny.toml`
  only.
- `tools/linux/check-dependency-sources.py`: every crate taken from git is,
  file by file, the crates.io release upstream's lockfile uses.

The cargo-deny version is the one upstream's development container installs
(`lib/firecracker/tools/devctr/Dockerfile`); the script refuses any other. It
also refuses to run when `lib/firecracker/deny.toml` is not the file
`tools/deny.toml` was made from (the hash in `tools/deny.toml`): after a
rebase, carry upstream's changes over and update the hash.

An advisory is fixed by moving to a fixed version of the crate (`cargo update
-p <crate>` in lib/firecracker, then amend the lockfile patch, and list the
move with its advisory in `tools/linux/dependency-moves.txt`, which the
Linux unit-test comparison checks), not by ignoring it. An `ignore` entry is accepted only for an advisory upstream
ignores in its own `deny.toml`, with upstream's reason. A new git source or a
second version of a crate needs an entry in `tools/deny.toml` that says why.

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
files, runs the dependency checks, then builds and packages the macOS binary
(`tools/package-release.sh`) and checks that it reports the tag. Hosted
runners cannot run Hypervisor.framework guests, so run the L3 scenarios on a
Mac before tagging.

A release has the archive, an SBOM, `SHA256SUMS` and signed build provenance
([SECURITY.md](SECURITY.md#verifying-a-release)). Each job of the workflow has
only the permissions it needs: the build can read the repository, a separate
job signs the attestations, and the last one, which runs no code from the
repository, publishes. Actions are pinned by full commit SHA (CI checks it);
update the SHA and its version comment together.

What a release is built with is pinned: the Rust toolchain is upstream's
(`lib/firecracker/rust-toolchain.toml`, installed by rustup on first use),
every build is `--locked` to `Cargo.lock` (upstream's `tools/release.sh`,
which has no `--locked`, is checked to leave the lockfile unchanged in CI),
and the release tools are installed with `cargo install --locked` at fixed
versions (cargo-deny at upstream's, cargo-cyclonedx at the one in
`tools/common.sh`). The SBOM is the same for the same commit on every
machine. The binary is not yet checked to be bit-for-bit reproducible, and
the runner image (`macos-15`) is GitHub's and changes over time.

## Tests

| Level | What | Where |
|---|---|---|
| L1 | upstream unit tests + compatibility crate tests | CI (three OSes); on Linux x86_64 (KVM) and aarch64 against plain upstream |
| L2 | upstream integration tests that work on nested KVM | Linux CI against plain upstream: a subset on every push, the functional and security suites weekly |
| L2' | all of upstream's tests, including performance | a Linux machine, before a release |
| L3 | API-driven scenarios: boot and serial, vsock, block, shutdown | Linux CI, a Mac, a Windows PC |

- On Linux, wick must match plain upstream (`patches/base`, no patches)
  **test by test**, run the same way on the same machine.
  `tools/linux/unit-tests.sh` runs upstream's unit tests as upstream's CI
  does (its development container, as root, musl, `RUST_TEST_THREADS=1`,
  `cargo test --all` and `--examples`) and `tools/linux/compare-unit-tests.py`
  compares the results by package, target and name;
  `tools/linux/integration-tests.sh` and
  `tools/linux/compare-integration-tests.py` do the same for upstream's
  pytest suites (`tools/test.sh` on upstream's musl release build). A test
  that passes on upstream and fails on wick is a wick bug: fix it, never
  exclude it. Tests that fail on plain upstream on the CI runner are listed,
  with the reason, in `tools/linux/unit-test-exclusions.txt` and
  `tools/linux/integration-test-exclusions.txt`. An informational step of
  the same job (never counted, never failing it) runs the vsock and balloon
  tests whose memory macOS compares with Linux's, and `test_cpuid` (1, 2 and
  16 vCPUs) and `test_all_vcpus_online`, whose memory Windows compares, with
  `tools/linux/integration/wick_memdiag.py` (`WICK_IT_MEMDIAG=1`): the
  VMM's own memory at its peak, by kind of mapping, in the step summary.
- On macOS, `tools/macos/check-unit-tests.py` runs every crate's unit tests
  but the jailer's (which need root) as CI's runners do, without
  Hypervisor.framework, and fails on any failure
  `tools/macos/unit-test-differences.txt` does not list with its reason, on a
  listed test that passes, and on a listed name that is not a test. A test
  that creates a VM is listed `no-hvf`; `tools/macos/test.sh` runs it on a
  Mac, signed, in a process of its own. With `--out DIR` it keeps each
  crate's output and every test's result by name (`tests.tsv`); CI's `macos`
  job uploads them as the `macos-unit-tests` artifact.
- On Windows, `tools/windows/check-unit-tests.py` runs every package's unit
  tests the same way (one at a time, `--no-fail-fast`; on CI's `windows`
  job) and fails on any failure not listed, with its reason, in
  `tools/windows/unit-test-differences.txt`, on a listed test that passes and
  on an entry that names no test. CI's runner has WHP; a test that makes a
  VM and fails there but must pass on the WHP PC is listed as `whp-pc` with
  its measured cause, and with `--whp`, on the PC, it must pass (none is
  listed at present: each failure there has a cause of another kind). The
  job's first step, "Host", prints the runner's processor, Windows build
  and whether WHP is there; its step "WHP tests on the runner", after the
  kit's upload, prints WHP's capabilities and runs kvm-ioctls' tests that
  need WHP (`#[ignore]`d in `cargo test`), libc's records of an AF_UNIX bind
  of each path form and of what a non-blocking pipe takes of a write, and
  the vmm's record of the network endpoint's descriptor check, each alone in
  a process of its own; its last step, "Standard input on a console", runs
  wick-os's console test on a hidden console of its own. On a WHP machine run one as
  `cargo test --manifest-path crates/compat/kvm-ioctls/Cargo.toml
  [--features gdb] -- --include-ignored --exact --nocapture <test>`.
- On macOS, `tools/macos/integration-tests.sh` runs upstream's pytest suites
  against the macOS release build and `tools/macos/compare-integration-tests.py`
  compares them test by test with their results on Linux
  (`tools/macos/integration-linux-baseline.txt`, from the Linux CI). Every
  test that passes on Linux passes on macOS or is listed, with its root-caused
  reason, in `tools/macos/integration-test-differences.txt`: a wick bug (fix
  it), a Linux feature macOS does not have yet (its `docs/PORTING.md` row), an
  x86_64-only test, or what the host cannot do (and why). Upstream's framework
  is unchanged but for one patch to `tests/conftest.py` (and one test,
  `test_api_version`, accepts the `+wick.N` version: patches/0015); the macOS host side
  (process waiting, memory maps, networks and their host side, the jailer's stand-in for
  runs without root) is `tools/macos/integration/`. Without arguments it runs
  the functional and security suites as the user; `--jailer` runs them as root
  with wick's jailer, as upstream's CI does on Linux (it asks for sudo itself,
  and refuses to start under sudo). `WICK_IT_DIAG_MEMORY=1`
  (each memory reading `get_stable_rss_mem` takes logged with its parts, the
  host's paging and the guest's `/proc/meminfo`, in `OUT/memory-diag.jsonl`),
  `WICK_IT_DIAG_RSS_LESS=vmm` (that reading without the VMM's own part too;
  it always leaves out the VMM's dyld shared cache part)
  and `WICK_IT_DEFER_MEMORY_ERROR=1` (the memory monitor's error at a kill
  inside a test held to the test's end, so the steps after the kill run; the
  test still fails) make a diagnostic run: `provenance.txt` says so, the
  comparison counts it as a problem, and no count or "passes" in the docs
  comes from it.
- `tools/linux/boot-test.sh` runs the first stages of
  `tools/windows/boot-test.ps1` on Linux: it boots upstream's CI guest with the musl release binary (seccomp filters on
  every thread) and checks serial I/O, SMP, the Async (io_uring) block engine
  and vsock.
- `tools/linux/jailer-cgroup-check.py` measures, as root in the Linux CI, what
  upstream's jailer does with the freezer and devices cgroup options (v1
  `freezer.state` and `devices.*` on mounted v1 hierarchies, v2
  `cgroup.freeze`), the reference the other hosts' jailers follow: it asserts
  each exit code and error text and prints them.
- Upstream tests left out on purpose: `test_licenses.py::test_for_valid_licenses`
  (wick's copyright headers), `tests/integration_tests/performance/`
  (baselines measured on AWS bare metal), and in CI the 5.10 and 6.18 guest
  kernel variants of the integration tests (6.1, upstream's default, runs).

## Fuzzing

wick's own code that takes input from a guest, or from another process,
has fuzz targets in `fuzz/` (cargo-fuzz: libFuzzer with AddressSanitizer
and overflow checks). The crate is standalone, with its own workspace, and
compiles wick's sources directly, so upstream's workspace does not change.

| Target | Code | Input | Checked against |
|---|---|---|---|
| `vnet_segment` | `overlay/vmm/platform/vnet.rs` | any virtio-net header and frame a guest can put on its TX queue | a reference written from Linux in `fuzz/src/frame.rs` (`skb_checksum_help`, `tcp_gso_segment`, UFO, `ip6_find_1stfragopt`) |
| `vnet_offload` | the same | well-formed frames with checksum offload, TSO or UFO, as a guest's offloads make them | the same reference; every such frame is accepted, and the checksums of the segments and of the datagram the fragments reassemble to verify |
| `hvf_exit` | `crates/compat/kvm-ioctls/src/hvf/exit.rs` | the exits a guest makes the Hypervisor.framework run loop decode: any exception syndrome, store register, device data, PSTATE and PSCI function id | a reference written from the Arm ARM (ESR_EL2, AArch64 loads and stores, the exception vectors) and the function ids of PSCI up to 1.1, SMCCC, KVM's vendor services, PV time and the TRNG service: exit class, MMIO size, bytes stored and register loaded, the debug registers' state, undefined accesses |
| `uffd_protocol` (macOS) | `crates/compat/libc/src/wick_uffd.rs` | the requests and records a page fault handler process sends | the state Linux's `UFFDIO_*` leave memory in; no descriptor left open |
| `whp_irqchip` | `crates/compat/kvm-ioctls/src/whp/irqchip.rs` (built on any host) | any sequence of the port and MMIO accesses the WHP run loop hands it (PICs, ELCR, PIT, speaker port, I/O APIC), interrupt lines, MSI routes, PIT state from a snapshot file, and a snapshot at any point | a VM restored from the snapshot saves the same state and answers every later access as the original does (but for what follows the host clock); each MSI's interrupt request carries its vector and destination |
| `whp_exit` | `crates/compat/kvm-ioctls/src/whp/exit.rs` (built on any host) | the fields of a sequence of WHP vCPU exits, which the guest controls | a reference written from the x86 architecture (the Intel SDM: port I/O sizes, 32-bit register writes zero-extending, `WRMSR` taking `EDX:EAX`, CPUID's OSXSAVE and OSPKE) and KVM's hypercall ABI: instruction length, port and memory access direction, size and kind, MSR accesses, the `RAX` an `IN` leaves, the hypercall answered (`-KVM_EPERM` from any privilege level but 0, the low 32 bits outside 64-bit code, as KVM) |

```sh
tools/fuzz.sh                          # every target this host runs, 60 s each
tools/fuzz.sh -t 3600 -j 4 vnet_offload
```

`tools/fuzz.sh --toolchain` names the pinned nightly the targets build with;
cargo-fuzz comes from `cargo install cargo-fuzz --locked`. CI runs every
target for a minute on Linux, macOS and Windows (`uffd_protocol` on macOS
only; `hvf_exit` not on Windows, where a source it compiles calls
`getentropy`, which the Windows POSIX layer does not have). On Windows the
script runs from Git Bash and needs Visual Studio's "C++ AddressSanitizer"
component, whose runtime DLL it finds and puts on `PATH`. And
`tools/fuzz.sh` fails when a target of `fuzz/Cargo.toml` is run on no host
without a reason in its `not_run()`. An input that fails is saved in
`fuzz/artifacts/<target>/`, and
`cargo +<toolchain> fuzz run --fuzz-dir fuzz <target> <file>` runs it again.

- A bug a target finds is fixed with a unit test in the crate that fails
  without the fix; the corpus is not a test.
- New code that parses what a guest or another process sends gets a
  target, through the code's public API, with a reference to check it
  against where one exists.

## Pull requests

- One change per pull request, with a test that fails without it: a unit test in the crate, an interface test in
  `platform::<iface>::tests` that runs against every backend, or a scenario in the boot tests.
- Say which hosts you built and tested on. A change to a macOS backend needs a `tools/macos/boot-test.sh` run; a
  change to a Windows backend that you could not run on a WHP machine should say so, and someone with one will.
- Tests leave nothing behind. A test script registers every process it
  starts as soon as it starts it, kills them on any exit (SIGTERM and SIGHUP
  included), writes `summary.txt` ending `N passed, M failed`, and calls
  `prepare_test_run` from `tools/common.sh`, which runs `tools/clean.sh`
  and checks for free disk space first. `tools/clean.sh --dry-run` shows
  what earlier runs left; `--all` also removes the build output.
- Reviewing a pull request means reading the code behind each claim it
  makes, for every host column it touches, not only that the other columns
  did not change.
- Run the checks CI runs: `tools/patches.sh check`, the build and clippy for your host, the compatibility crates'
  tests (`.github/workflows/ci.yml` has the exact commands), and `tools/check-dependencies.sh` if you changed a
  `Cargo.toml` or `Cargo.lock`.

By contributing, you agree that your work is licensed under the project's license (Apache-2.0).
