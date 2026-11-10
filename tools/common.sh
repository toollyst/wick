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
