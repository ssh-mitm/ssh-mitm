#!/usr/bin/env bash
# Builds the Sphinx documentation locally, the same way Read the Docs does
# (see .readthedocs.yaml) -- install the hash-pinned doc toolchain plus
# ssh-mitm itself, regenerate the API reference, then build HTML. Useful
# to preview doc changes without pushing and waiting on an RTD build.
#
# Two separate `pip install` calls: pip's hash-checking mode, once
# triggered by pylock.docs.toml's hashes, demands every requirement in
# that same invocation carry one -- mixing in the unhashed local project
# would fail outright. See doc/develop/reproducible-builds.md.
#
# Usage: packaging/build-docs.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Installing from a pylock.toml needs pip >= 26.1; older pip doesn't
# recognize the format at all and errors out trying to parse it as a
# classic requirements.txt.
python3 -m pip install pip==26.2.1
python3 -m pip install --require-hashes -r pylock.docs.toml
python3 -m pip install .
sphinx-apidoc -T -e -M -d 1 -o doc/develop/api sshmitm
sphinx-build doc build/html

echo "==> done: build/html/index.html"
