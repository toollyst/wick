# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Shared helpers for wick's scripts. Source, don't execute.

WICK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM_DIR="$WICK_ROOT/lib/firecracker"
PATCHES_DIR="$WICK_ROOT/patches"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/firecracker-microvm/firecracker.git}"
# The local branch in lib/firecracker that holds the patch series as commits.
WICK_BRANCH="wick"

die() {
    echo "error: $*" >&2
    exit 1
}

# git in the upstream checkout. Commits made by the tools (git am, rebase) get
# an identity even on a machine without git config.
up() {
    git -C "$UPSTREAM_DIR" \
        -c user.name="${GIT_COMMITTER_NAME:-$(git config user.name || echo wick)}" \
        -c user.email="${GIT_COMMITTER_EMAIL:-$(git config user.email || echo wick@localhost)}" \
        "$@"
}

# The upstream release tag the patches apply to (patches/base).
upstream_base() {
    tr -d '[:space:]' <"$PATCHES_DIR/base"
}

# wick's fix release number on top of the upstream base (patches/version):
# 0 for the release of the base itself.
wick_number() {
    local n
    n="$(tr -d '[:space:]' <"$PATCHES_DIR/version")" || die "cannot read patches/version"
    [[ "$n" =~ ^(0|[1-9][0-9]*)$ ]] || die "patches/version must hold wick's release number (0, 1, 2, ...), not '$n'"
    echo "$n"
}

# wick's version: the upstream release (1.18.0) for number 0, then
# <upstream>+wick.<N> (1.18.0+wick.1) for wick's fix releases, which never sort
# below the upstream release. The binaries report the same string
# (crates/version reads the same two files at build time).
wick_version() {
    local base n
    base="$(upstream_base)"
    n="$(wick_number)" || exit 1
    if [[ "$n" == 0 ]]; then
        echo "${base#v}"
    else
        echo "${base#v}+wick.$n"
    fi
}

# The patch files, in order (patches/series).
series() {
    grep -v '^\s*\(#\|$\)' "$PATCHES_DIR/series"
}

# Make sure an upstream release tag exists in lib/firecracker (the submodule
# is shallow, so tags are fetched one at a time).
ensure_tag() {
    local tag="$1"
    up rev-parse -q --verify "refs/tags/$tag^{commit}" >/dev/null && return 0
    up fetch -q --no-tags --depth 1 "$UPSTREAM_URL" "refs/tags/$tag:refs/tags/$tag" \
        || die "cannot fetch tag $tag from $UPSTREAM_URL"
}

# The upstream commit wick records for lib/firecracker (the submodule pointer).
recorded_upstream() {
    git -C "$WICK_ROOT" ls-files -s lib/firecracker | awk '$1 == "160000" { print $2 }'
}

# The cargo-deny version upstream's development container installs
# (lib/firecracker/tools/devctr/Dockerfile); wick's dependency checks use the
# same (tools/check-dependencies.sh).
cargo_deny_version() {
    local v
    v="$(sed -n 's/.*cargo install --locked cargo-deny --version \([0-9][0-9.]*\).*/\1/p' \
        "$UPSTREAM_DIR/tools/devctr/Dockerfile")"
    [[ -n "$v" ]] || die "cannot find the cargo-deny version in lib/firecracker/tools/devctr/Dockerfile"
    echo "$v"
}

# The cargo-cyclonedx version that writes the release SBOM
# (tools/package-release.sh).
CARGO_CYCLONEDX_VERSION=0.5.9
