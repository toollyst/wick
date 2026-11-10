## What and why

<!-- One change. What it does, and the problem it solves. -->

## Tested on

<!-- Which hosts you built and ran it on: macOS (chip), Windows (WHP or not), Linux (arch, KVM or not). -->

## Checks

- [ ] `tools/patches.sh check` passes; every upstream change is in a patch with a `wick:` comment
- [ ] Build and clippy on my host; compatibility crate tests for the crates I touched
- [ ] A test that fails without this change
- [ ] Touches a macOS backend: `tools/macos/boot-test.sh` passes
- [ ] Touches a Windows backend: run `tools/windows/boot-test.ps1` on WHP, or said above that I couldn't
- [ ] Changes behavior on a host: the roadmap and docs say so
