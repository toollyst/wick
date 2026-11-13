#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Package a macOS (Apple silicon) release of wick in the upstream
# Firecracker release layout (lib/firecracker/tools/release.sh).
#
#   tools/package-release.sh <tag> [out-dir]      (default out-dir: dist)
#
# Produces, for tag T and S = T-darwin-aarch64:
#   <out>/wick-S.tgz, holding release-S/ with
#       <bin>-S for each binary of MACOS_RELEASE_BINS (tools/common.sh):
#           release builds; those of MACOS_RELEASE_HV_BINS signed with the
#           Hypervisor.framework entitlement, the others ad hoc as the linker
#           signs them; each reports "<name> T" (--version)
#       firecracker_spec-T.yaml   the API specification (its version T's)
#       <template>-T.json         MACOS_RELEASE_CPU_TEMPLATES
#       LICENSE, NOTICE, THIRD-PARTY
#       SHA256SUMS                every other file in release-S/
#   <out>/wick-S.tgz.sha256.txt
#       "<hex>  wick-S.tgz"  (checked with `shasum -a 256 -c`)
#   <out>/<bin>-S.cdx.json for each binary
#       its SBOM: CycloneDX 1.5, every crate it is built from on
#       aarch64-apple-darwin, as Cargo.lock pins it (cargo-cyclonedx, the
#       version in tools/common.sh)
#
# Left out of upstream's layout, as tools/common.sh says: seccompiler-bin and
# the seccomp filter JSON (no seccomp-BPF on macOS), the x86_64 CPU templates,
# and the .debug files: the binaries are Mach-O, with their symbols in them
# (upstream's release profile, strip = "none"), and the release profile makes
# no DWARF to split off.
#
# The build is `cargo build --locked` with upstream's toolchain
# (lib/firecracker/rust-toolchain.toml).
#
# The binaries need macOS 15 or later on Apple silicon (hv_gic_*). The signature
# is ad hoc and not notarized. A copy downloaded by a browser carries
# com.apple.quarantine, which tar copies onto what it extracts; one fetched with
# curl does not. If macOS refuses to run it, `xattr -d com.apple.quarantine` on
# the archive (or -dr on the extracted directory) clears it (README.md).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
ROOT="$WICK_ROOT"

tag="${1:-}"
out="${2:-dist}"
[[ -n "$tag" ]] || die "usage: $0 <tag> [out-dir]"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(\+wick\.[1-9][0-9]*)?$ ]] \
    || die "tag must look like v1.18.0 or v1.18.0+wick.1 (got '$tag')"
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] \
    || die "needs macOS on Apple silicon"

# The tag must be the version the binaries report: the upstream release wick
# tracks (patches/base) and wick's number (patches/version).
version="$(wick_version)"
[[ "$tag" == "v$version" ]] \
    || die "tag $tag is not v$version (patches/base $(upstream_base), patches/version $(wick_number))"
command -v cargo-cyclonedx >/dev/null \
    || die "cargo-cyclonedx not found: cargo install --locked cargo-cyclonedx --version $CARGO_CYCLONEDX_VERSION"
cyclonedx="$(cargo-cyclonedx cyclonedx --version)"
[[ "$cyclonedx" == *" $CARGO_CYCLONEDX_VERSION" ]] \
    || die "need cargo-cyclonedx $CARGO_CYCLONEDX_VERSION, found '$cyclonedx'"

suffix="$tag-darwin-aarch64"
name="wick-$suffix"
dir="release-$suffix"
fc="$ROOT/lib/firecracker"
target_dir="${CARGO_TARGET_DIR:-$fc/build/cargo_target}"

needs_hv() {
    local b
    for b in "${MACOS_RELEASE_HV_BINS[@]}"; do [[ "$b" == "$1" ]] && return 0; done
    return 1
}

# Build (release profile), and sign those that create a VM.
packages=()
for bin in "${MACOS_RELEASE_BINS[@]}"; do packages+=(-p "$bin"); done
(cd "$fc" && CARGO_TARGET_DIR="$target_dir" MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-15.0}" \
    cargo build --locked --release "${packages[@]}" --bins)
for bin in "${MACOS_RELEASE_HV_BINS[@]}"; do
    codesign --force --sign - --entitlements "$ROOT/tools/macos/hypervisor.entitlements" \
        "$target_dir/release/$bin"
done

# Each binary: a valid signature, the entitlement exactly where it is needed,
# and the tag as its version (the first line of `--version`, as upstream's
# check_bin_artifact reads it; not `| head`, which can cut the writer off).
check_bin() {
    local path="$1" bin="$2" reported
    codesign --verify --strict "$path" || die "$path: the signature does not verify"
    if needs_hv "$bin"; then
        codesign -d --entitlements - "$path" 2>/dev/null | grep -q com.apple.security.hypervisor \
            || die "$path is not signed with the hypervisor entitlement"
    elif codesign -d --entitlements - "$path" 2>/dev/null | grep -q com.apple.security; then
        die "$path has entitlements; only ${MACOS_RELEASE_HV_BINS[*]} should"
    fi
    reported="$("$path" --version)"
    reported="${reported%%$'\n'*}"
    [[ "${reported##* }" == "$tag" ]] || die "$path reports '$reported', not version $tag"
}

mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"; rm -f "$fc"/src/*/*_bin.cdx.json' EXIT
mkdir "$stage/$dir"
for bin in "${MACOS_RELEASE_BINS[@]}"; do
    check_bin "$target_dir/release/$bin" "$bin"
    cp "$target_dir/release/$bin" "$stage/$dir/$bin-$suffix"
    # The copy must keep the signature (it is embedded in the Mach-O).
    check_bin "$stage/$dir/$bin-$suffix" "$bin"
done
spec="$fc/src/firecracker/swagger/firecracker.yaml"
spec_version="$(sed -n 's/^  version: *//p' "$spec")"
[[ "$tag" == "v$spec_version" || "$tag" == "v$spec_version+"* ]] \
    || die "$spec is version $spec_version, not $tag's"
cp "$spec" "$stage/$dir/firecracker_spec-$tag.yaml"
for template in "${MACOS_RELEASE_CPU_TEMPLATES[@]}"; do
    cp "$fc/tests/data/custom_cpu_templates/$template.json" "$stage/$dir/$template-$tag.json"
done
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$fc/THIRD-PARTY" "$stage/$dir/"
(cd "$stage/$dir" && find . -type f -not -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort \
    | xargs shasum -a 256 >SHA256SUMS && shasum -a 256 -c SHA256SUMS >/dev/null)

# No AppleDouble (._*) files; owner and group normalised.
(cd "$stage" && COPYFILE_DISABLE=1 tar --uid 0 --gid 0 --uname root --gname wheel \
    -czf "$out/$name.tgz" "$dir")
(cd "$out" && shasum -a 256 "$name.tgz" >"$name.tgz.sha256.txt" \
    && shasum -a 256 -c "$name.tgz.sha256.txt" >/dev/null)

# The SBOMs, from Cargo.lock. cargo-cyclonedx writes one file per binary next
# to each package's manifest and has no --locked: the lockfile must come out
# unchanged. The timestamp is the commit's (SOURCE_DATE_EPOCH); tools/sbom.py
# checks every component against Cargo.lock.
lock="$(shasum -a 256 "$fc/Cargo.lock")"
rm -f "$fc"/src/*/*_bin.cdx.json
for bin in "${MACOS_RELEASE_BINS[@]}"; do
    (cd "$fc" && SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct)" \
        cargo cyclonedx -qq --manifest-path "src/$bin/Cargo.toml" --describe binaries \
            --target aarch64-apple-darwin --spec-version 1.5 --format json)
    python3 -I "$ROOT/tools/sbom.py" "$fc/src/$bin/${bin}_bin.cdx.json" "$out/$bin-$suffix.cdx.json" \
        "$ROOT" "$fc/Cargo.lock" "$bin" || die "$bin's SBOM does not match Cargo.lock"
done
[[ "$(shasum -a 256 "$fc/Cargo.lock")" == "$lock" ]] || die "cargo-cyclonedx changed Cargo.lock"

echo "$out/$name.tgz"
echo "$out/$name.tgz.sha256.txt"
for bin in "${MACOS_RELEASE_BINS[@]}"; do echo "$out/$bin-$suffix.cdx.json"; done
