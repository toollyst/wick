# wick documentation

| Read | When you want to |
| --- | --- |
| [getting-started.md](getting-started.md) | Boot your first microVM: build, guest images, config file, REST API, networking |
| [ROADMAP.md](ROADMAP.md) | See what works on each host, what is next, and what "done" means for each milestone |
| [../SECURITY.md](../SECURITY.md) | Know how each of Firecracker's controls is held on each host, and what is not at parity yet |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Understand the design: the layers, the compatibility crates, the POSIX layer on Windows |
| [PORTING.md](PORTING.md) | Write or check a host backend: each Linux facility, its macOS backend, the test that proves it, and where Windows stands |
| [macos-memory-limit.md](macos-memory-limit.md) | Know what the jail's memory limit counts on macOS, and why it bounds a compromised VMM's guest memory but not its own: the mechanics, the measurements, the public sources and the fix (guest RAM as owned purgeable chunks, with discard and reclaim) |
| [windows-jail-reach.md](windows-jail-reach.md) | Know what a jailed Firecracker reaches on Windows beyond its files: the devices, system services and names its token opens, measured from inside a real jail, how Linux's jail compares, and the fix planned |
| [design-fs.md](design-fs.md) | Read the plan for sharing host folders with a guest (virtio-fs): the risks, the fix planned on each host, the tests meant to prove it. No code yet |
| [design-gpu.md](design-gpu.md) | Read the plan for giving a guest the host's GPU (headless Vulkan): the stages, the risks and what stays open on each host. No code yet |
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
  fs/                     host folder sharing (a workspace of its own): frame/, the VMM↔server frames
tools/                    everything you run by hand or in CI (below)
  macos/                  run, test, boot-test, jailer-test and the integration harness on Apple silicon
  windows/                boot test, jailer test, integration harness and host probes for a Windows PC
  linux/                  upstream's unit and integration tests on Linux, compared with plain upstream
  vhost-user-blk/         a vhost-user-blk backend for the boot, jailer and integration tests
fuzz/                     fuzz targets for wick's own code (a crate of its own, CONTRIBUTING.md "Fuzzing")
docs/                     these pages
.github/workflows/        ci.yml (every push and pull request), release.yml (tags v*),
                          linux-restore-repro.yml (by hand: restores of a Linux smp snapshot)
```

Cargo always runs in `lib/firecracker`. Upstream's workspace is the only workspace: its patched manifest lists
`crates/compat/*`, `crates/ext` and `crates/version` as members, so there is one `Cargo.lock` and one set of lints.
The exceptions build outside Firecracker: `fuzz/`, `tools/vhost-user-blk/` and `crates/fs/` (host folder sharing,
[design-fs.md](design-fs.md)). `crates/fs` is a workspace of its own so that its file server will never link the
compatibility `libc`; it uses Firecracker's toolchain and lints, and cargo runs from `crates/fs`.
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
| `userfaultfd` | the userfaultfd API | on the userfaultfd kernel side in the compatibility `libc` | the same, on its Windows kernel side (`libc::wick_uffd`, `windows_uffd.rs`) |
| `memfd` | memfd and seals | an unlinked POSIX shared memory object, of a random name and mode `0` | an unnamed temporary file; size seals are sections |
| `os`, `std` | `std::os::{unix, fd}` | re-exported | the same traits and types on handles |
| `vm-memory`, `event-manager`, `micro-http`, `vhost` | rust-vmm crates | the original | upstream's source with mechanical rewrites, generated |

## Everyday commands

```sh
tools/setup.sh                          # after cloning and after pulling changes to patches/
cd lib/firecracker
cargo build -p firecracker              # build
cargo clippy -p vmm -p firecracker -p wick-ext -p jailer --lib --bins --tests -- -D warnings
cargo doc --no-deps -p vmm -p firecracker -p jailer  # wick's modules (overlay/) deny broken doc links; ci.yml's "Rustdoc links" step also checks crates/
cd ../..

tools/macos/test.sh                     # upstream's vmm unit tests with Hypervisor.framework (macOS); a blocked test child's stacks only with WICK_TEST_STACKS=1, as sample can raise the Developer Tools dialog
tools/macos/boot-test.sh                # scenario tests in a real guest (macOS), before any change to a macOS backend; refuses to start under sudo (before macOS 26 its vmnet stage alone asks for sudo)
sudo -v && tools/macos/jailer-test.sh   # the jailer's scenario tests (macOS): builds as you, then runs them as root; refuses to start under sudo
tools/macos/root-batch.sh               # every macOS run that needs root, one password prompt (--list: the steps and what each proves); refuses to start under sudo
tools/patches.sh export                 # after committing a change on branch `wick` in lib/firecracker
tools/patches.sh check                  # what CI checks about patches/
```

The table below has the tools a contributor runs; [`tools/README-unlisted.txt`](../tools/README-unlisted.txt)
lists the rest (what another tool or a CI step runs, probes, records) with why, and `tools/check-claims.py`
fails on a tool in neither. Every script under `tools/` (with `tools/linux/`, `tools/macos/` and
`tools/windows/`) says what it does in its own header.

| Tool | What it does |
| --- | --- |
| [`tools/setup.sh`](../tools/setup.sh) | Checks out upstream at `patches/base` and applies the series as commits on branch `wick` (`--force` discards local commits) |
| [`tools/patches.sh`](../tools/patches.sh) | `export` writes `patches/` from branch `wick`; `check` verifies it matches, that every changed upstream file carries a `wick:` comment, that the submodule is at `patches/base`, and that README.md and docs/ARCHITECTURE.md count the series and its files right |
| [`tools/guest-counter-warp.py`](../tools/guest-counter-warp.py) | Run in a Linux guest by the boot tests of all three hosts: two CPUs' counters (the TSC; the virtual counter on aarch64) against each other by the kernel's TSC warp check's algorithm, bounded by time as the kernel's is (2 s, at most 500000 turns), one pass or FAIL line naming the ticks and the time it ran; its header states the interface and how it is sent; its machine code is built from [`tools/guest-counter-warp-loop.c`](../tools/guest-counter-warp-loop.c), and its header names the clang and the command |
| [`tools/check-guest-counter-warp.py`](../tools/check-guest-counter-warp.py) | Rebuilds that machine code with clang and compares it byte for byte with what the guest tool carries: pass with the recorded Apple clang 21.0.0 (this Mac, both machines); a loud SKIP (exit 3) without clang or with another clang, such as Ubuntu 24.04's 18.1.3, which builds other bytes |
| [`tools/rebase.sh`](../tools/rebase.sh) | Moves the series to a new upstream tag (`--finish` after resolving conflicts) |
| [`tools/macos/run.sh`](../tools/macos/run.sh) | Builds, signs with the Hypervisor.framework entitlement and runs `firecracker` |
| [`tools/macos/test.sh`](../tools/macos/test.sh) | Runs unit tests with the entitlement (through [`sign-and-run.sh`](../tools/macos/sign-and-run.sh) as the cargo runner) |
| [`tools/macos/check-unit-tests.py`](../tools/macos/check-unit-tests.py) | Runs every crate's unit tests but the jailer's as CI's runners do (no Hypervisor.framework) and fails on a failure [`unit-test-differences.txt`](../tools/macos/unit-test-differences.txt) does not list, a listed test that passes, a listed name that is not a test, a crate whose counts are not the `count` line the list's header gives it, or a file the tests leave in their own endpoint directory that [`unit-test-litter.txt`](../tools/macos/unit-test-litter.txt) does not list; `--out` keeps every test's result by name (CI's `macos-unit-tests` artifact); `--list-only` checks the `count` lines against the tests' listing without running them, before a push; `--selftest` |
| [`tools/macos/boot-test.sh`](../tools/macos/boot-test.sh) | Scenario tests against upstream's aarch64 CI guest: boot, SMP, block, vsock, net, vmnet, snapshots, snapshot-permissions (a snapshot into a directory Firecracker cannot write, a restore from files it cannot read: upstream's errors), diff, uffd, PCI, vhost-user, vhost-user-hotplug (a vhost-user drive hot-plugged after the sandbox narrows), devices (logger, metrics, MMDS, balloon, entropy, rate limiter), balloon (cycles after a restore from file and on a booted guest: the guest keeps the host's pages, the footprint follows the balloon), restores (one snapshot restored and snapshotted again 20 times, for races between vCPU threads), hugepages, api-process, cli (exit codes, start time flags, logger and metrics on FIFOs), tools (`rebase-snap`, `snapshot-editor`), no-seccomp, memory-hotplug (virtio-mem), cpu-templates (V1N1 and a custom template through `PUT /cpu-config`), pvtime (PV steal time: on macOS 27 its figures, elsewhere that it is not offered). A Firecracker that answers that its VMM ended is waited for, so its reason is in its log, and one the harness kills while it runs is named in the stage's summary line and its log; `python3 -I tools/macos/boot-test.py --selftest` checks that against a stand-in, with no VM |
| [`tools/macos/timer-coalescing.py`](../tools/macos/timer-coalescing.py) | How late the process's 50 ms timers fire, by kind of wait (a condition variable, a `kevent` timeout, kqueue timers with and without `NOTE_CRITICAL`): whether and how much the host coalesces timers (the macOS unit-test step's evidence). Informational: it never fails |
| [`tools/macos/seatbelt-kill-probe.py`](../tools/macos/seatbelt-kill-probe.py) | Seatbelt's `(with send-signal SIGKILL)` action alone, with a one-rule profile and no wick code: whether a denied system call and Mach trap end the process inside the call, read from its exit reason. CI's macos-seatbelt job runs it on macOS 15 and 26 beside the sandbox's own test, to tell a change in Seatbelt from one in wick (passed in CI run 43497862443). It prints, and fails only if the action does not do what macOS 27.2 measured |
| [`tools/macos/watchdog.py`](../tools/macos/watchdog.py) | Runs a command, and if it is still running at a limit prints every process it started (`ps`) and, with `WICK_TEST_STACKS=1`, each one's thread stacks (`sample`), kills them and fails: CI's macOS test steps run under it, so a hang ends its step with the evidence before the job's timeout. CI's macOS jobs set `WICK_TEST_STACKS=1`; without it (a desktop Mac) the stacks are left out and said so, as `sample` asks for the task port and can raise the Developer Tools Access dialog and wait behind it, so a queue of jobs would stop there. The same variable asks the vmm sandbox tests' blocked-child helper, `jailer-test.py` and `jailer-cgroup-test.py` for a hung process's stacks; `WICK_WATCHDOG_NO_SAMPLE=1`, the old name, still turns the watchdog's off |
| [`tools/macos/guest-timer.py`](../tools/macos/guest-timer.py) | How much longer than asked a guest's 1 ms and 20 ms sleeps take: the guest's view of the host's timer coalescing, under the launcher's policy (`taskpolicy -b` shows a background Firecracker's guest). Boots boot-test's guest. Informational: it never fails |
| [`tools/macos/api-vmm-ended-test.py`](../tools/macos/api-vmm-ended-test.py) | A request in flight when the VMM ends (patches/0050): the build held on a FIFO drive until the request is in the VMM's channel, then failed; checks the 500, exit code 1 and the build's error on standard error. Any host with FIFOs; CI runs it on Linux and macOS |
| [`tools/macos/jailer-test.sh`](../tools/macos/jailer-test.sh) | The jailer's scenario tests, as root: refused options, `devices` cgroup options refused as upstream refuses them on Linux, the freezer (a jail frozen and thawed through upstream's cgroup files), uid/gid and chroot, files outside the jail, daemonize, `--new-pid-ns`, jetsam, CPU and resource limits read back, `fsize`, a jailed guest booted without and with the API, on its own network (`--netns`), vmnet from a jail, killed past its memory limit, held to its CPU limit, on huge pages, restored through a uffd handler and with a vhost-user drive |
| [`tools/macos/root-batch.sh`](../tools/macos/root-batch.sh) | The macOS runs that need root in one go, with one password prompt: first the root-owned leftovers of earlier root runs given back, then the jailer's unit tests as root, jailer-test's netns, freeze, fsize, vmnet-guest and jail, test_serial_dos under the jailer, sudo's descriptor limit, guest-timer.py at idle levels 0 and 128 (the level put back), and boot-test vmnet before macOS 26. A failed step does not stop the rest; logs and summary.txt in build/root-batch/<time>; it fails if any root-owned file is left in the repository. `--list`, `--only STEP`, `--selftest` (CI runs it) |
| [`tools/macos/integration-tests.sh`](../tools/macos/integration-tests.sh) | Upstream's integration tests against the macOS release build (`--jailer`: as root, with wick's jailer), compared test by test with upstream's results on Linux by [`compare-integration-tests.py`](../tools/macos/compare-integration-tests.py) |
| [`tools/macos/gdb-test.sh`](../tools/macos/gdb-test.sh) | Firecracker's gdb stub (the gdb feature's build) with boot-test's guest and a gdb client, lldb too when present; [`gdb-test.py`](../tools/macos/gdb-test.py) says what it checks |
| [`tools/macos/sandbox-discovery.sh`](../tools/macos/sandbox-discovery.sh) | Checks the sandbox's run-phase lists in `overlay/vmm/ext/sandbox.rs` against what a running microVM asks the kernel for: a build of its own that reports instead of refusing, run through boot-test.sh; fails on any call or operation outside the lists |
| [`tools/linux/boot-test.sh`](../tools/linux/boot-test.sh) | Boots upstream's x86_64 CI guest with wick on Linux (KVM) and checks, stage by stage, what the Windows boot test's first stages check: Linux's reference (CI's linux-boot job). A Firecracker that answers that its VMM ended is waited for, so its reason is in its log, and one that does not exit within the bound is a failed check, killed, its log saying so; `tools/linux/boot-test.sh --selftest` checks that against a stand-in, with no VM, and linux-boot runs it before the guest stages, which reach that path only on such an answer |
| [`tools/linux/guest-kernel.sh`](../tools/linux/guest-kernel.sh) | Builds upstream's CI guest kernel (6.1 or 6.18, from a pinned Amazon Linux tag, with upstream's configuration chain and patches) with wick's fragments on top, today `CONFIG_VIRTIO_FS` for host folder sharing; fails if a fragment line is not in the built configuration. CI's `guest-kernels` job runs it on x86_64 and arm64 and hands the kernels on as `guest-kernels-<arch>`; `plan` prints what it would build without downloading |
| [`tools/linux/fs-userns-check.py`](../tools/linux/fs-userns-check.py) | The verdict of the fs job's step that runs wick-fsd's confined tests as the runner's user under an AppArmor profile granting user namespaces (design-fs §6.1): from each test binary's whole output, every binary passed, none ran nothing confined, and each other "ran nothing" line is one it knows, printed with why; `--selftest` (fed a CI run's own lines) runs in CI's Results readers step |
| [`tools/linux/unit-tests.sh`](../tools/linux/unit-tests.sh) | Upstream's unit tests as upstream's CI runs them (its development container, musl, `RUST_TEST_THREADS=1`), for plain upstream or wick; [`compare-unit-tests.py`](../tools/linux/compare-unit-tests.py) compares the two (CI's linux-unit-tests job) |
| [`tools/linux/integration-tests.sh`](../tools/linux/integration-tests.sh) | Upstream's integration tests as upstream's `tools/devtool test` runs them, for plain upstream or wick; [`compare-integration-tests.py`](../tools/linux/compare-integration-tests.py) compares the two (CI's linux-integration-tests job) |
| [`tools/windows/boot-test.ps1`](../tools/windows/boot-test.ps1) | Scenario tests against upstream's x86_64 CI guest on WHP ([steps](../tools/windows/README.md)): boot, SMP, block, vsock, net, snapshots, diff, uffd, PCI, restores, vhost-user, hugepages, devices, balloon, api-process, cli, tools, no-seccomp, memory-hotplug, cpu-templates, and its own `foreign-snapshot` and `gdb`. Not yet: the macOS stages `vhost-user-hotplug` (a vhost-user drive hot-plugged after the sandbox narrows) and `snapshot-permissions`. `vmnet` is macOS's, and `pvtime` aarch64's (upstream's `functional/test_pvtime.py` runs on aarch64 only). A Firecracker that answers that its VMM ended is waited for, so its reason is in its log, and one the harness kills while it runs is named in the stage's summary line and its logs (jailer-test.ps1 the same, on its summary line); `boot-test.ps1 -SelfTest`'s `ending` case checks that against a stand-in, with no VM |
| [`tools/windows/jailer-test.ps1`](../tools/windows/jailer-test.ps1) | The jailer's scenario tests on WHP: refused options, the freezer (a jail frozen and thawed through upstream's cgroup files), the jail's isolation, a file hard-linked into three jails, bind links into the jail, links, handles, daemonize, pidns, netns, the API process, Job Object limits, hugepages, uffd and vhost-user under the jailer ([stages](../tools/windows/README.md)) |
| [`tools/windows/check-ps.py`](../tools/windows/check-ps.py) | Checks the Windows PowerShell scripts on macOS or Linux, before they reach Windows: compiles every `Add-Type`'s C# with Mono's `mcs` as Windows PowerShell 5.1 compiles it (C# 5), each alone and each script's together (a type defined twice), and refuses a function defined twice in one scope and a non-ASCII script without a byte order mark; not the PowerShell itself (`--selftest` tests its checks) |
| [`tools/windows/winprobe.c`](../tools/windows/winprobe.c) | Measures the Windows mechanisms the sandbox and jailer backends use |
| [`tools/windows/integration-tests.ps1`](../tools/windows/integration-tests.ps1) | Upstream's integration tests against the Windows build, as the macOS script runs them, compared with upstream's results on Linux by [`compare-integration-tests.py`](../tools/windows/compare-integration-tests.py) |
| [`tools/windows/check-unit-tests.py`](../tools/windows/check-unit-tests.py) | Every package's unit tests on Windows against [`unit-test-differences.txt`](../tools/windows/unit-test-differences.txt), as the macOS check does; `--whp` on the WHP PC |
| [`tools/gen-windows-sources.sh`](../tools/gen-windows-sources.sh) | Generates the Windows builds of the rust-vmm crates and of `polling` (`--check` in CI) |
| [`tools/gen-kvm-bindings-windows.sh`](../tools/gen-kvm-bindings-windows.sh) | Generates `kvm-bindings` with the Linux x86_64 layout for Windows (`--check` in CI) |
| [`tools/package-release.sh`](../tools/package-release.sh) | Packages a macOS release in upstream's release layout, with each binary's SBOM ([`tools/sbom.py`](../tools/sbom.py) checks it against `Cargo.lock`) |
| [`tools/check-unit-graph.py`](../tools/check-unit-graph.py) | Without a build: wick's Linux builds compile every crate upstream's do with upstream's features, and the macOS builds are their baseline in [`tools/unit-graph`](../tools/unit-graph) (`--selftest`; CI's patches job; before a push) |
| [`tools/check-dependencies.sh`](../tools/check-dependencies.sh) | Dependency checks: advisories, licenses, banned and duplicate crates, sources ([CONTRIBUTING.md](../CONTRIBUTING.md#dependencies)) |
| [`tools/fuzz.sh`](../tools/fuzz.sh) | Runs the fuzz targets in `fuzz/` for a given time each (`-t SECONDS`, `-j JOBS`) |
| [`tools/clean.sh`](../tools/clean.sh) | What every test script runs at its start: kills a test run's processes and the shell tools' loops left by a killed run (parent pid 1), removes test directories no process names, and says how many; `--dry-run` lists without touching |
| [`tools/check-background-loops.py`](../tools/check-background-loops.py) | Fails a loop a shell tool under `tools/` starts in the background without a liveness test of its owner, a numeric bound and a `# background loop:` comment (CI, with `--selftest`) |
| [`tools/check-claims.py`](../tools/check-claims.py) | That the docs name what exists and what checks it: test names, stages, paths, cited commits and headings, table cells, this table's completeness, and status claims that name no test (CI's patches job) |
| [`tools/check-derived.py`](../tools/check-derived.py) | That the numbers the docs derive from the tree (README's line count, PORTING row 1's counts) are the tree's (CI's patches job) |
| [`tools/check-tree.py`](../tools/check-tree.py) | Fails a tracked file, a patch included, that points into the directory where the agents keep their notes (not in the repository), and a Markdown table row whose number of cells differs from its header's or that does not end in `\|` (CI's patches job, with `--selftest`) |
| [`tools/libtest-results.py`](../tools/libtest-results.py) | The results of one test binary's run as libtest's own process gave them, where a test that runs its binary again as a child has the child's lines in the same output (on Windows the same console, on macOS a failed parent's message): a name's first result is the parent's, the parent's failures list (just before its last `test result:` line) overrides, a test it began with no result of its own passed if that adds up to libtest's counts, and a section that does not add up is named; read by `compare-unit-tests.py` (and so `ci-results.py`) and `tools/macos/check-unit-tests.py`; `--selftest` has the Windows, macOS and self-run cases |
| [`tools/ci-results.py`](../tools/ci-results.py) | Each test's result in one format, `results.tsv` (run, commit, job, host, CPU, test, result), read from what a job already writes (libtest's output, pytest's JSON report, a scenario script's summary.txt, check-unit-tests.py's tests.tsv, macOS's and Windows'); the Linux, macOS and Windows jobs upload it as `results-<job>`; a failure the job expects is `xfail` with the job's own evidence (`add --xfail NAME=REASON`); `validate` checks a file of it; `collect RUN_ID` is the only writer of [`docs/evidence/runs.tsv`](evidence/runs.tsv), the rows of the tests the documents name, against which check-claims holds the documents' run claims (the phrases: [`tools/run-claims.txt`](../tools/run-claims.txt)); `--selftest` checks its readers on cuts of real CI logs ([`ci-results-fixtures/`](../tools/ci-results-fixtures/)) |
| [`tools/compat-counts.py`](../tools/compat-counts.py) | Writes and checks the generated parts of docs/COMPATIBILITY.md: progress per host and the counts per upstream test file (`--check` in CI) |

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
| Which advisories, licenses, crates and sources the dependencies may have | [`tools/deny.toml`](../tools/deny.toml), from upstream's `lib/firecracker/deny.toml` |
| What a release contains and how it is signed | [`.github/workflows/release.yml`](../.github/workflows/release.yml), [SECURITY.md](../SECURITY.md#verifying-a-release) |
