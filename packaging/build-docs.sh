#!/usr/bin/env bash
# Builds the Sphinx documentation locally, the same way Read the Docs does
# (see .readthedocs.yaml) -- install doc/requirements.txt plus ssh-mitm
# itself, regenerate the API reference, then build HTML. Useful to preview
# doc changes without pushing and waiting on an RTD build.
#
# Usage: packaging/build-docs.sh
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pip install -r doc/requirements.txt .
sphinx-apidoc -T -e -M -d 1 -o doc/develop/api sshmitm
sphinx-build doc build/html

echo "==> done: build/html/index.html"
