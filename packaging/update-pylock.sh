#!/usr/bin/env bash
# Regenerates pylock.toml, the hash-pinned lock of ssh-mitm's own runtime
# dependencies (see doc/develop/reproducible-builds.md). Wraps `pip lock .`
# with two fixups pip's lock command doesn't handle on its own:
#
#   1. `pip lock .` also emits a `[packages.directory]` self-entry for
#      ssh-mitm itself, which has no hash and makes
#      `pip install --require-hashes -r pylock.toml` fail outright -- the
#      AppImage build installs ssh-mitm separately, so this entry is
#      dropped.
#   2. The AppImage bundles the `appimage` package itself (used for its
#      own --appimage-extract-style self-update), which is not one of
#      ssh-mitm's own dependencies and so never appears in a plain
#      `pip lock .` -- this re-adds it, pinned to the exact
#      appimage_version/appimage_sha256 from [tool.appimage] in
#      pyproject.toml (cross-checked against the real PyPI wheel hash).
#
# Must run under the same Python minor version [tool.appimage].python in
# pyproject.toml pins (see doc/develop/reproducible-builds.md for why) --
# defaults to `python3.11`, override with PYLOCK_PYTHON.
#
# Usage: packaging/update-pylock.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PYTHON="${PYLOCK_PYTHON:-python3.11}"
command -v "$PYTHON" >/dev/null || {
    echo "$PYTHON not found -- set PYLOCK_PYTHON to a Python 3.11 interpreter" >&2
    exit 1
}

"$PYTHON" -m pip lock . -o pylock.toml

"$PYTHON" - <<'PYEOF'
import json
import re
import tomllib
import urllib.request

with open("pyproject.toml", "rb") as f:
    appimage_cfg = tomllib.load(f)["tool"]["appimage"]

version = appimage_cfg["appimage_version"]
expected_sha256 = appimage_cfg["appimage_sha256"]

with open("pylock.toml") as f:
    content = f.read()

# pip lock . adds a self-referencing directory entry for ssh-mitm itself,
# which has no hash and breaks `pip install --require-hashes`.
content, n = re.subn(
    r'\[\[packages\]\]\nname = "ssh-mitm"\n\n\[packages\.directory\]\npath = "\."\n\n?',
    "",
    content,
)
if n != 1:
    raise SystemExit(f"expected exactly one ssh-mitm self-entry to strip, found {n}")

with urllib.request.urlopen(f"https://pypi.org/pypi/appimage/{version}/json", timeout=30) as r:
    data = json.load(r)
wheel = next(u for u in data["urls"] if u["packagetype"] == "bdist_wheel")
if wheel["digests"]["sha256"] != expected_sha256:
    raise SystemExit(
        f"appimage {version} wheel hash on PyPI ({wheel['digests']['sha256']}) doesn't "
        f"match appimage_sha256 in pyproject.toml ({expected_sha256}) -- "
        "pyproject.toml's pin may be stale, re-run `python -m appimage.ctl update-tools` first"
    )

appimage_block = (
    "[[packages]]\n"
    'name = "appimage"\n'
    f'version = "{version}"\n\n'
    "[[packages.wheels]]\n"
    f'name = "{wheel["filename"]}"\n'
    f'url = "{wheel["url"]}"\n\n'
    "[packages.wheels.hashes]\n"
    f'sha256 = "{expected_sha256}"\n\n'
)

# Insert alphabetically, matching pip lock's own ordering of the rest of
# the file -- find the first existing package block that sorts after
# "appimage" and insert immediately before it.
block_names = re.findall(r'\[\[packages\]\]\nname = "([^"]+)"', content)
insert_before = next((name for name in sorted(block_names) if name > "appimage"), None)
if insert_before is None:
    raise SystemExit("could not find an insertion point for the appimage package block")
marker = f'[[packages]]\nname = "{insert_before}"\n'
content = content.replace(marker, appimage_block + marker, 1)

with open("pylock.toml", "w") as f:
    f.write(content)

print("==> re-added appimage pin, stripped ssh-mitm self-entry")
PYEOF

echo "==> done: pylock.toml"
