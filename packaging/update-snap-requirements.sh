#!/usr/bin/env bash
# Regenerates requirements-snap.txt, the hash-pinned set of ssh-mitm's
# runtime dependencies consumed by snapcraft.yaml's python part
# (python-requirements). See doc/develop/reproducible-builds.md for the
# full rationale.
#
# Unlike pylock.toml (used for the AppImage build), this is a classic
# pip-compile --generate-hashes output with no --python-platform
# restriction: pip-compile pins the hash of *every* wheel/sdist PyPI
# published for the resolved version, not just the one matching the
# machine that ran this script. pip then picks whichever file matches
# the install target's platform/Python version and verifies it against
# the matching hash. That's what lets a single file cover both amd64 and
# arm64 snap builds, generated from any machine -- unlike pylock.snap.toml
# (removed), which pinned exactly one (Python version, platform) wheel
# and had to be regenerated per architecture.
#
# This buys hash-verified integrity, not bit-identical reproducibility --
# ssh-mitm only guarantees the latter for the AppImage build (see "Known
# limits" in doc/develop/reproducible-builds.md).
#
# Usage: packaging/update-snap-requirements.sh [--upgrade]
#   --upgrade   move pins forward to the latest versions satisfying
#               requirements.in's bounds. A plain re-run keeps existing
#               pins stable (pip-compile's own in-place-compile behavior).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v pip-compile >/dev/null || {
    echo "pip-compile not found -- pip install pip-tools" >&2
    exit 1
}

UPGRADE=()
[ "${1:-}" = "--upgrade" ] && UPGRADE=(--upgrade)

pip-compile --generate-hashes --allow-unsafe --no-emit-find-links \
    "${UPGRADE[@]}" requirements.in -o requirements-snap.txt

echo "==> done: requirements-snap.txt"
