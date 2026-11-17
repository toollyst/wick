# The tools docs/README.md's tools table does not list, each with why: what
# runs it (another tool or a CI step), or what kind of probe or record it is.
# tools/check-claims.py fails on a tool (a .sh, .py, .ps1, .c or .rs file
# directly in tools/, tools/linux/, tools/macos/ or tools/windows/) in
# neither the table nor this file, on one in both, and on a line here without
# a reason or naming no tool.
#
# path reason
tools/common.sh sourced by the shell tools for their shared helpers; not run
tools/check-record-features.sh run by CI's windows job ("No record-only feature in the kit's product binaries") and by release.yml
tools/gen-windows-sources-polling.py run by tools/gen-windows-sources.sh: its one change to polling
tools/linux/check-dependency-sources.py run by tools/check-dependencies.sh
tools/linux/devctr.sh run by tools/linux/unit-tests.sh and integration-tests.sh: upstream's development container
tools/linux/guest-ram-grain.c a record (LINUXGRAIN lines), run by CI's linux-boot job, "Guest RAM by the host's THP setting (records)"
tools/linux/guest-ram-record.py a record (GUESTRAM lines), run by the same linux-boot step
tools/linux/jailer-cgroup-check.py a measurement of upstream's jailer on Linux, run by CI's linux job; tools/macos/jailer-cgroup-test.py follows it
tools/linux/make-vmstate.py run by CI's linux-boot job: the snapshot state file the other hosts' foreign-snapshot tests refuse
tools/macos/boot-test.py run through tools/macos/boot-test.sh, which builds and signs the binaries
tools/macos/enclave-refusal-test.py run by CI's "Nitro Enclave refused without the device" steps (linux-boot, macos)
tools/macos/foreign-snapshot-test.py run by CI's macos job, "A snapshot made on Linux x86_64 is refused"
tools/macos/jailer-cgroup-test.py jailer-test stages, run through tools/macos/jailer-test.sh
tools/macos/jailer-test.py run through tools/macos/jailer-test.sh, which builds as the invoking user
tools/windows/enclave-refusal-test.py run by CI's windows job, "Nitro Enclave refused without the device"
tools/windows/jail-parent.rs built by CI's windows job ("Build the probes"), used by tools/windows/jailer-test.ps1
tools/windows/jail-probe.rs built by CI's windows job ("Build the probes"), run by tools/windows/jailer-test.ps1 as the jailed binary
tools/windows/fs-probe.rs a probe, run by hand as an elevated administrator: what each confinement considered for the virtio-fs server reaches on a Windows host (docs/design-fs.md §6.3), and, run by the jailer as the jailed binary (`devjail`), what the Windows jail's token reaches (docs/windows-jail-reach.md); built by CI's windows job ("Build the probes")
tools/windows/job-freeze-probe.ps1 a probe: whether a Job Object's processes freeze and thaw as a group
tools/windows/memory-partition-probe.rs a probe: whether a memory partition bounds what a jailed process takes, built by CI's windows job
tools/windows/mitigation-audit.ps1 a probe: the Windows sandbox's measure-then-enforce loop, the counterpart of tools/macos/sandbox-discovery.sh
tools/windows/vmm-memory-record.py a record of Firecracker's own memory on Windows, run by CI's windows job
