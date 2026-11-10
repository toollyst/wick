#!/usr/bin/env bash
# Copyright 2026 toollyst contributors.
# SPDX-License-Identifier: Apache-2.0
#
# Runs a command in upstream's development container (the image and tag that
# lib/firecracker/tools/devtool names), with the docker flags upstream's
# `devtool test` uses: privileged, seccomp unconfined, the host's /dev and
# /boot, a /srv scratch space and upstream's ulimits. Upstream's own unit
# tests, release builds and integration tests run in this container, so wick
# runs them there too.
#
#   tools/linux/devctr.sh [-v DIR]... [-w DIR] [--chown DIR]... -- CMD...
#
#   -v DIR       also mount DIR (the wick checkout always is), at the same path
#   -w DIR       working directory (default: lib/firecracker)
#   --chown DIR  give DIR back to the calling user afterwards (the container
#                runs as root, like upstream's)
#
# Paths are the same inside and outside the container, so logs and paths
# printed by cargo mean the same on the host.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../common.sh"

mounts=("$WICK_ROOT")
workdir="$UPSTREAM_DIR"
chown_dirs=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -v) mounts+=("$(cd "$2" && pwd)"); shift 2 ;;
        -w) workdir="$(cd "$2" && pwd)"; shift 2 ;;
        --chown) mkdir -p "$2"; chown_dirs+=("$(cd "$2" && pwd)"); shift 2 ;;
        --) shift; break ;;
        *) die "unknown argument: $1" ;;
    esac
done
[[ $# -gt 0 ]] || die "no command given"

devtool="$UPSTREAM_DIR/tools/devtool"
repo="$(sed -n 's/^DEVCTR_IMAGE_NO_TAG="\(.*\)"$/\1/p' "$devtool")"
tag="$(sed -n 's/^DEVCTR_IMAGE_TAG=\${DEVCTR_IMAGE_TAG:-\(.*\)}$/\1/p' "$devtool")"
[[ -n "$repo" && -n "$tag" ]] || die "cannot read the devctr image from $devtool"
image="$repo:${DEVCTR_IMAGE_TAG:-$tag}"

if [[ -z "$(docker images -q "$image")" ]]; then
    echo "pulling $image" >&2
    for i in 1 2 3 4 5; do
        docker pull -q "$image" && break
        ((i < 5)) || die "cannot pull $image"
        sleep 3
    done
fi

# The cargo registry persists across runs, as devtool keeps it in build/.
cache="${WICK_DEVCTR_CACHE:-$UPSTREAM_DIR/build/devctr-cache}"
mkdir -p "$cache/registry" "$cache/git"
chown_dirs+=("$cache")

args=(
    --rm
    --privileged
    --security-opt seccomp=unconfined
    --ulimit core=0
    --ulimit nofile=4096:4096
    --ulimit memlock=-1:-1
    --volume /dev:/dev
    --volume /boot:/boot
    --volume "$cache/registry:/usr/local/rust/registry"
    --volume "$cache/git:/usr/local/rust/git"
    --env PYTHONDONTWRITEBYTECODE=1
    --workdir "$workdir"
)
for m in "${mounts[@]}"; do
    args+=(--volume "$m:$m")
done
# /srv is a tmpfs, as in devtool: the tests hardlink within it and copy
# across file systems.
args+=(--tmpfs /srv:exec,dev,size=32G)
[[ -t 0 ]] && args+=(-i)
[[ -t 1 ]] && args+=(-t)

# Run the command, then hand the files it made back to the caller, keeping
# the command's exit status.
uid_gid="$(id -u):$(id -g)"
exec docker run "${args[@]}" "$image" bash -c '
    git config --global --replace-all safe.directory "*"
    owner="$1"; shift
    ndirs="$1"; shift
    dirs=("${@:1:$ndirs}"); shift "$ndirs"
    "$@"
    rc=$?
    ((${#dirs[@]})) && chown -R "$owner" "${dirs[@]}"
    exit $rc
' devctr "$uid_gid" "${#chown_dirs[@]}" "${chown_dirs[@]}" "$@"
