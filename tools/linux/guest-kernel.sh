#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Builds upstream Firecracker's CI guest kernel with wick's fragments on top:
# the kernel the virtio-fs boot stages boot (docs/design-fs.md, row 21),
# for this host's architecture (x86_64: vmlinux; aarch64: the Image, named
# vmlinux-* as upstream's CI names its aarch64 kernels).
#
#   tools/linux/guest-kernel.sh build VERSION OUT_DIR
#   tools/linux/guest-kernel.sh plan VERSION      # what build would do; no download
#   tools/linux/guest-kernel.sh check CONFIG      # wick's fragments are in a built .config
#
# VERSION: 6.1 (upstream's default CI kernel) or 6.18.
#
# What upstream's resources/rebuild.sh does for a CI kernel, minus what makes
# its result move: rebuild.sh takes the newest Amazon Linux tag of the
# version at the time it runs and the whole repository; this takes the tag
# pinned below, checks that it is still the commit recorded here, and
# fetches that commit alone (--depth 1). The configuration is upstream's
# chain as rebuild.sh concatenates it (microvm-kernel-ci-ARCH-VERSION.config,
# ci.config, nvme.config, efi.config), then wick's fragments
# (tools/linux/guest-kernel-*.config), resolved by `make olddefconfig`;
# upstream's kernel patches for the version (resources/patches/*/VERSION)
# are applied first, as rebuild.sh applies them. A fragment line that
# olddefconfig drops or changes (an unmet dependency) fails the build: a
# kernel without what the fragment asks for is never produced.
#
# Output in OUT_DIR: vmlinux-<release>-wick and vmlinux-<release>-wick.config.
#
# Needs: Linux x86_64 or aarch64, git, make, gcc, bc, flex, bison, libelf and
# libssl headers (Ubuntu: bc flex bison gcc make libelf-dev libssl-dev), and
# github.com for the source (about 230 MB at depth 1).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"

AL_URL="https://github.com/amazonlinux/linux"
CONFIGS="$UPSTREAM_DIR/resources/guest_configs"
KPATCHES="$UPSTREAM_DIR/resources/patches"
FRAGMENTS=("$WICK_ROOT/tools/linux/guest-kernel-virtio-fs.config")

# The Amazon Linux tag of each version, and the commit it names (peeled).
# Picked 2026-11-17 by rebuild.sh's own rule (get_tag): the newest
# microvm-kernel tag of 6.1, the newest kernel*6.18*amzn2023 tag of 6.18.
# 6.1.188 is the release of the kernel upstream's CI bucket has
# (tools/linux/boot-test.sh, vmlinux-6.1.188). A new pin is a new cache key.
pin() {
    case "$1" in
    6.1) echo "microvm-kernel-6.1.188-56.393.amzn2023 8785eb28815fdac7e6743bb6fad34ef67dc24b26" ;;
    6.18) echo "kernel6.18-6.18.62-127.179.amzn2023 b7522fb67989bd879de78486e9e253fd2f21f1dd" ;;
    *) die "unknown kernel version '$1' (6.1 or 6.18)" ;;
    esac
}

host_arch() {
    case "$(uname -m)" in
    x86_64) echo x86_64 ;;
    aarch64 | arm64) echo aarch64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
    esac
}

# Upstream's configuration chain for VERSION on ARCH, then wick's fragments.
config_chain() {
    local version="$1" arch="$2" f
    f="$CONFIGS/microvm-kernel-ci-$arch-$version.config"
    [[ -f "$f" ]] || die "no upstream configuration $f"
    echo "$f"
    for f in ci nvme efi; do
        [[ -f "$CONFIGS/$f.config" ]] || die "no upstream configuration $CONFIGS/$f.config"
        echo "$CONFIGS/$f.config"
    done
    printf '%s\n' "${FRAGMENTS[@]}"
}

kernel_patches() {
    local version="$1" p
    for p in "$KPATCHES"/*/"$version"/*.patch; do
        [[ -f "$p" ]] && echo "$p"
    done
    return 0
}

# Every line of wick's fragments, as it is in the .config `make` resolved.
check_config() {
    local config="$1" fragment line failed=0
    [[ -f "$config" ]] || die "no configuration $config"
    for fragment in "${FRAGMENTS[@]}"; do
        while IFS= read -r line; do
            [[ "$line" =~ ^CONFIG_ ]] || continue
            if grep -qxF "$line" "$config"; then
                echo "ok: $line"
            else
                echo "MISSING: $line (the built .config has: $(grep -E "^(# )?${line%%=*}[= ]" "$config" || echo nothing))"
                failed=1
            fi
        done <"$fragment"
    done
    ((failed == 0)) || die "$config lacks lines of wick's fragments"
}

plan() {
    local version="$1" arch tag sha
    arch="$(host_arch)"
    read -r tag sha < <(pin "$version")
    echo "version: $version ($arch)"
    echo "source:  $AL_URL tag $tag = $sha"
    echo "configs:"
    config_chain "$version" "$arch" | sed 's/^/  /'
    echo "patches:"
    kernel_patches "$version" | sed 's/^/  /'
}

build() {
    local version="$1" out="$2" arch tag sha src target image release
    arch="$(host_arch)"
    read -r tag sha < <(pin "$version")
    mkdir -p "$out"
    out="$(cd "$out" && pwd)"
    src="$out/src-$version"
    rm -rf "$src"
    git init -q "$src"
    git -C "$src" fetch -q --depth 1 "$AL_URL" "refs/tags/$tag:refs/tags/$tag"
    local got
    got="$(git -C "$src" rev-parse "refs/tags/$tag^{commit}")"
    [[ "$got" == "$sha" ]] || die "$AL_URL's tag $tag is $got now, not the pinned $sha: check the change and pin it again"
    git -C "$src" -c advice.detachedHead=false checkout -q "$sha"
    local p
    while IFS= read -r p; do
        echo "applying $p"
        git -C "$src" apply "$p"
    done < <(kernel_patches "$version")

    # As rebuild.sh: the files concatenated, later values over earlier ones.
    local chain=()
    while IFS= read -r p; do chain+=("$p"); done < <(config_chain "$version" "$arch")
    awk 1 "${chain[@]}" >"$src/.config"
    make -C "$src" -s olddefconfig
    check_config "$src/.config"

    case "$arch" in
    x86_64) target=vmlinux image=vmlinux ;;
    aarch64) target=Image image=arch/arm64/boot/Image ;;
    esac
    make -C "$src" -s -j "$(nproc)" "$target"
    release="$(cat "$src/include/config/kernel.release")"
    # As rebuild.sh: the version up to its last digit (6.1.188-56.393.amzn2023 -> 6.1.188...).
    release="$(sed -E 's/(.*[[:digit:]]).*/\1/' <<<"$release")"
    cp "$src/$image" "$out/vmlinux-$release-wick"
    cp "$src/.config" "$out/vmlinux-$release-wick.config"
    rm -rf "$src"
    ls -l "$out/vmlinux-$release-wick" "$out/vmlinux-$release-wick.config"
}

case "${1:-}" in
build) (($# == 3)) || die "usage: $0 build VERSION OUT_DIR"; build "$2" "$3" ;;
plan) (($# == 2)) || die "usage: $0 plan VERSION"; plan "$2" ;;
check) (($# == 2)) || die "usage: $0 check CONFIG"; check_config "$2" ;;
*) die "usage: $0 build VERSION OUT_DIR | plan VERSION | check CONFIG" ;;
esac
