#!/usr/bin/env bash
# Proves ssh-mitm's own wheel build is actually bit-identical across two
# independent builds, rather than just assuming it from hash-pinning
# alone -- the actual claim reproducible builds make. Run before a
# release. See doc/reproducible-builds.md.
#
# Usage: packaging/verify-reproducible-build.sh
set -euo pipefail
cd "$(dirname "$0")/.."

DIST_A=$(mktemp -d)
DIST_B=$(mktemp -d)
trap 'rm -rf "$DIST_A" "$DIST_B"' EXIT

for DIST in "$DIST_A" "$DIST_B"; do
    echo "==> building into $DIST"
    python3 -m pip wheel \
        --build-constraint requirements-build.txt \
        --no-deps -w "$DIST" . --quiet
done

WHEEL_A=("$DIST_A"/ssh_mitm-*.whl)
WHEEL_B=("$DIST_B"/ssh_mitm-*.whl)

SHA_A=$(sha256sum "${WHEEL_A[0]}" | cut -d' ' -f1)
SHA_B=$(sha256sum "${WHEEL_B[0]}" | cut -d' ' -f1)

if [ "$SHA_A" != "$SHA_B" ]; then
    echo "NOT REPRODUCIBLE: two independent builds produced different wheels" >&2
    echo "  ${WHEEL_A[0]}: $SHA_A" >&2
    echo "  ${WHEEL_B[0]}: $SHA_B" >&2
    exit 1
fi

echo "OK: bit-identical wheel across two independent builds ($SHA_A)"
