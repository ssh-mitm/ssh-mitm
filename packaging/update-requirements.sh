#!/usr/bin/env bash
# Regenerates requirements-build.txt, the hash-pinned set of PEP 518 build
# dependencies (hatchling, hatch-requirements-txt, and their transitive
# deps) used to make ssh-mitm's PyPI wheel reproducibly buildable via
# `pip wheel --build-constraint requirements-build.txt`. See
# doc/reproducible-builds.md for the full rationale.
#
# No wheelhouse detour here (unlike some projects' equivalent script):
# hatchling/hatch-requirements-txt and their transitive deps (packaging,
# pathspec, pluggy, trove-classifiers) are all pure-Python packages with a
# single universal wheel, so `pip-compile --generate-hashes` already
# resolves exactly one hash per package on its own -- the wheelhouse
# restriction only matters for packages with multiple platform-specific
# wheels (C extensions), which none of these are.
#
# Usage: packaging/update-requirements.sh [--upgrade]
#   --upgrade   move pins forward to the latest version satisfying
#               pyproject.toml's build-system bounds. A plain re-run keeps
#               existing pins stable (pip-compile's own in-place-compile
#               behavior).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v pip-compile >/dev/null || {
    echo "pip-compile not found -- pip install pip-tools" >&2
    exit 1
}

UPGRADE=()
[ "${1:-}" = "--upgrade" ] && UPGRADE=(--upgrade)

pip-compile --all-build-deps --only-build-deps --generate-hashes \
    --allow-unsafe --no-emit-find-links "${UPGRADE[@]}" \
    pyproject.toml -o requirements-build.txt

echo "==> done: requirements-build.txt"
