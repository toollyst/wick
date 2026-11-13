#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# The patch series (CONTRIBUTING.md, "Changing upstream code").
#
#   tools/patches.sh export   write patches/ from the commits on branch `wick`
#                             in lib/firecracker (one commit = one patch;
#                             $WICK_BRANCH names another: tools/common.sh)
#   tools/patches.sh check    patches/ is what `export` writes, every hunk
#                             changed upstream file has a `wick:` comment, and
#                             lib/firecracker is recorded at patches/base
#   tools/patches.sh list     the upstream files the series changes
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

base="$(upstream_base)"

# Format base..wick as patch files into a directory, plus the series file.
format_into() {
    # --full-index: abbreviated blob ids depend on how many objects the
    # checkout has (a shallow clone abbreviates less), full ones do not.
    local out="$1"
    ensure_tag "$base"
    up rev-parse -q --verify "refs/heads/$WICK_BRANCH" >/dev/null \
        || die "no branch $WICK_BRANCH in lib/firecracker; run tools/setup.sh"
    up format-patch -q --zero-commit --no-signature --no-numbered --full-index \
        -o "$out" "refs/tags/$base..refs/heads/$WICK_BRANCH"
    (cd "$out" && ls -1 *.patch 2>/dev/null) >"$out/series.list" || true
}

# Fingerprints compare the branch with patches/ without touching either.
fingerprint() {
    (cd "$1" && cat $(cat series.list) 2>/dev/null) | git hash-object --stdin
}

case "${1:-}" in
export)
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    format_into "$tmp"
    find "$PATCHES_DIR" -name '*.patch' -delete
    cp "$tmp"/*.patch "$PATCHES_DIR"/ 2>/dev/null || true
    {
        echo "# Applied in this order to upstream Firecracker $base (patches/base)"
        echo "# by tools/setup.sh. Written by tools/patches.sh export; do not edit."
        cat "$tmp/series.list"
    } >"$PATCHES_DIR/series"
    echo "exported $(wc -l <"$tmp/series.list" | tr -d ' ') patches to patches/"
    ;;
fingerprint-branch)
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    format_into "$tmp"
    fingerprint "$tmp"
    ;;
fingerprint-files)
    series >"$PATCHES_DIR/.series.list.tmp"
    trap 'rm -f "$PATCHES_DIR/.series.list.tmp"' EXIT
    (cd "$PATCHES_DIR" && cat $(cat .series.list.tmp)) | git hash-object --stdin
    ;;
check)
    errors=0
    ensure_tag "$base"
    [[ "$(recorded_upstream)" == "$(up rev-parse "refs/tags/$base^{commit}")" ]] \
        || { echo "FAIL lib/firecracker is not recorded at upstream $base (patches/base)"; errors=$((errors + 1)); }

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    format_into "$tmp"
    if ! diff -q <(series) "$tmp/series.list" >/dev/null; then
        echo "FAIL patches/series does not list the commits on $WICK_BRANCH (run tools/patches.sh export)"
        errors=$((errors + 1))
    fi
    while IFS= read -r p; do
        if ! cmp -s "$PATCHES_DIR/$p" "$tmp/$p"; then
            echo "FAIL patches/$p differs from its commit on $WICK_BRANCH (run tools/patches.sh export)"
            errors=$((errors + 1))
        fi
    done < <(series)

    # Every upstream file the series changes names the change with a `wick:`
    # comment, so `git grep wick:` in lib/firecracker finds them all
    # (Cargo.lock is generated and exempt).
    while IFS= read -r p; do
        bad="$(awk '
            /^diff --git / { if (file != "" && file != "Cargo.lock" && !marked[file]) seen[file] = 1
                             file = $4; sub(/^b\//, "", file); next }
            /^\+/ && /wick:/ { marked[file] = 1 }
            END { if (file != "" && file != "Cargo.lock" && !marked[file]) seen[file] = 1
                  for (f in seen) if (!marked[f]) print "  " f }
        ' "$PATCHES_DIR/$p")"
        if [[ -n "$bad" ]]; then
            echo "FAIL patches/$p changes files without a wick: comment:"
            echo "$bad"
            errors=$((errors + 1))
        fi
    done < <(series)

    # The documents that count the series say what it is: "N small patches
    # (... in M files)" in README.md, "N feature patches touching M files"
    # in docs/ARCHITECTURE.md.
    n="$(series | wc -l | tr -d ' ')"
    m="$("$0" list | wc -l | tr -d ' ')"
    for doc in README.md docs/ARCHITECTURE.md; do
        said="$(tr '\n' ' ' <"$WICK_ROOT/$doc" | grep -oE '[0-9]+ (small|feature) patches[^.]*[0-9]+ +files' | head -1 || true)"
        [[ -n "$said" ]] || { echo "FAIL $doc no longer counts the patches and the files they change"; errors=$((errors + 1)); continue; }
        if [[ "$said" != "$n "* || "$said" != *" $m files" && "$said" != *" $m  files" ]]; then
            echo "FAIL $doc says \"$said\", but the series is $n patches changing $m files"
            errors=$((errors + 1))
        fi
    done

    ((errors == 0)) || die "$errors problem(s) with patches/"
    echo "OK: $(series | wc -l | tr -d ' ') patches on upstream $base"
    ;;
list)
    while IFS= read -r p; do
        grep '^diff --git ' "$PATCHES_DIR/$p" | awk '{ sub(/^b\//, "", $4); print $4 }'
    done < <(series) | sort -u
    ;;
*)
    sed -n '4,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
