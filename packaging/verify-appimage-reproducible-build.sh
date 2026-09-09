#!/usr/bin/env bash
# Proves the AppImage build is actually bit-identical across two
# independent builds, rather than just assuming it from hash-pinning
# alone -- the actual claim reproducible builds make. Run before a
# release. See doc/develop/reproducible-builds.md.
#
# Usage: packaging/verify-appimage-reproducible-build.sh
set -euo pipefail
cd "$(dirname "$0")/.."

DIST_A=$(mktemp -d)
DIST_B=$(mktemp -d)
trap 'rm -rf "$DIST_A" "$DIST_B" build dist' EXIT

for DIST in "$DIST_A" "$DIST_B"; do
    echo "==> building into $DIST"
    rm -rf build dist
    hatch run appimage:build
    cp dist/ssh-mitm-x86_64.AppImage "$DIST/"
done

APPIMAGE_A=("$DIST_A"/*.AppImage)
APPIMAGE_B=("$DIST_B"/*.AppImage)

SHA_A=$(sha256sum "${APPIMAGE_A[0]}" | cut -d' ' -f1)
SHA_B=$(sha256sum "${APPIMAGE_B[0]}" | cut -d' ' -f1)

if [ "$SHA_A" != "$SHA_B" ]; then
    echo "NOT REPRODUCIBLE: two independent builds produced different AppImages" >&2
    echo "  ${APPIMAGE_A[0]}: $SHA_A" >&2
    echo "  ${APPIMAGE_B[0]}: $SHA_B" >&2
    exit 1
fi

echo "OK: bit-identical AppImage across two independent builds ($SHA_A)"
