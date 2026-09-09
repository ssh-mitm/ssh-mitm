# Reproducible Wheel Builds

The wheel published to [pypi.org](https://pypi.org/project/ssh-mitm/) is
built with `hatchling` and `hatch-requirements-txt` as the PEP 518 build
backend (`[build-system]` in `pyproject.toml`). This page covers how that
build is made hash-verified and provably bit-identical across independent
builds of the same commit.

`hatch build` works fine for a local build, but doesn't hash-verify the
build backend itself. The release workflow
(`.github/workflows/python-publish.yml`) instead uses the hash-verified
path this page documents directly: `python -m build --sdist
--no-isolation` for the sdist, `pip wheel --build-constraint
requirements-build.txt --no-deps` for the wheel.

## Hash-pinning the build dependencies

`packaging/requirements-build.txt` pins every build-time dependency
(`hatchling`, `hatch-requirements-txt`, and their transitive deps —
`packaging`, `pathspec`, `pluggy`, `tomlkit`, `trove-classifiers`,
`editables`) to an exact version *and* a sha256 hash. Passing it as a
[`--build-constraint`](https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-build-constraint)
makes pip verify every installed build-tool file against that hash before
using it, rather than trusting whatever the index currently serves:

```bash
pip wheel --build-constraint requirements-build.txt --no-deps .
```

`[build-system].requires` in `pyproject.toml` deliberately stays
unpinned (`["hatchling", "hatch-requirements-txt"]`) — the constraint
file is the single source of truth for exact versions, so there's nothing
to keep in sync by hand.

All of `hatchling`'s and `hatch-requirements-txt`'s build-time
dependencies are pure-Python packages with a single universal
(`py3-none-any`) wheel, so `pip-compile --generate-hashes` already
resolves exactly one hash per package on its own — no wheelhouse detour
needed (unlike packages with several platform-specific wheels, e.g. C
extensions, where an unrestricted `--generate-hashes` would pin every
platform variant at once).

Regenerate the file after changing `[build-system].requires` or to pick
up newer build-tool releases:

```bash
packaging/update-requirements.sh            # keep existing pins stable
packaging/update-requirements.sh --upgrade  # move pins forward
```

## Proving bit-identical builds

Hash-pinning proves every installed file is the one you expect — it
doesn't by itself prove the build *process* is deterministic. Run:

```bash
packaging/verify-reproducible-build.sh
```

This builds the wheel twice, independently, and compares
`sha256sum`. It should print:

```
OK: bit-identical wheel across two independent builds (<hash>)
```

Not part of the regular lint/test loop — building the wheel twice is too
slow for the everyday dev loop. `python-publish.yml` runs it automatically
before every release build; a failure aborts the release before anything
gets published.

## AppImage build

The `ssh-mitm-x86_64.AppImage` published on every release is built with the
[`appimage`](https://github.com/ssh-mitm/appimage) packaging tool, which
bundles a full Python interpreter, `ssh-mitm`, and its dependencies into a
single executable. Its own reproducibility story is independent of the
wheel build above, but pins in the same spirit: every input the tool
downloads is hash-verified before use.

```bash
hatch run appimage:build
```

This wraps `python -m appimage.ctl build`, reading the `[tool.appimage]`
table in `pyproject.toml`. The pins it enforces:

- `python_date`/`python_sha256` - the bundled
  [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
  interpreter
- `appimagetool_version`/`appimagetool_sha256` - the `appimagetool` binary
  used to package the AppDir
- `runtime_version`/`runtime_sha256` - the AppImage runtime stub
- `appimage_version`/`appimage_sha256` - the `appimage` runtime module
  bundled inside the AppImage itself (used for `--appimage-extract` style
  self-updates), separate from `appimagectl_version`, which records which
  release of the `appimage.ctl` build tool produced the pins
- `pylock`/`build_pylock` - hash-pinned installs of `ssh-mitm`'s own
  dependencies and the wheel build backend, via `pip install
  --require-hashes`

`pylock.toml` locks bare `.` - `ssh-mitm`'s regular `dependencies`, the
same loose ranges (`requirements.in`) any `pip install ssh-mitm` resolves
against. There's deliberately no extra or constraint file anchoring it to
a previous resolution: every `lock` run re-resolves fully fresh against
whatever's currently newest and compatible on the index, the same way a
plain `pip install ssh-mitm` would. That trades away pip-compile-style
"stays put until I explicitly upgrade" stability for having a single
source of truth - no separate `requirements.txt`/`production` extra to
keep in sync with it.

`reproducible = true`, `verify_downloads = true`, and `require_zsyncmake =
true` in `[tool.appimage]` turn all of the above into hard build failures
instead of warnings if a pin is missing or a download doesn't match.

Refresh the pins (new Python build, new `appimagetool` release, etc.) with:

```bash
python -m appimage.ctl update-tools
```

then rebuild and confirm `ssh-mitm-x86_64.AppImage` still works before
committing the updated `pyproject.toml`/`pylock.toml`.

`update-tools` can fail with a spurious `sha256 mismatch` against the
*old* pin instead of writing the new one, when the upstream artifact
(`appimagetool` in particular) has actually changed since the last pin -
exactly the case it exists to handle. If that happens, remove the stale
`appimagetool_version`/`appimagetool_sha256` (and any other affected
`*_version`/`*_sha256` pair) from `[tool.appimage]` and run
`python -m appimage.ctl enable-reproducible` instead, which re-pins from
scratch, regenerates `pylock.toml`, and only re-adds `reproducible = true`
once a real build succeeds.

```bash
packaging/verify-appimage-reproducible-build.sh
```

confirms the AppImage build is itself bit-identical, the same idea as
`verify-reproducible-build.sh` above but for the AppImage instead of the
wheel. `appimage-build.yml` runs it automatically before every release
build (not on a plain `workflow_dispatch` test run, to avoid the extra
build cost); a failure aborts the release before anything gets uploaded.

## Snap build

`snapcraft.yaml`'s `python` part installs from `pylock.snap.toml`
(`python-requirements`), hash-verified the same way `pylock.docs.toml`
is - no `--require-hashes` flag needed, consuming a pylock.toml enables
it automatically.

Unlike the other pylock files, this one **must** be regenerated on an
`ubuntu-24.04` runner (matching `base: core24`), not locally - pylock's
hashes pin exact wheel URLs for a specific (Python version, platform)
combination, and the snap build resolves against Ubuntu 24.04's Python
(3.12), not whatever's running `pip lock` locally:

```bash
python3 -m pip lock -r requirements.in -o pylock.snap.toml
```

Confirmed empirically: generating it with Python 3.13 locally pins
`cp313` wheels, which don't match what `core24`'s Python 3.12 needs. Run
the command above as a step in `ubuntu-24.04` CI (e.g. `snapcore/action-build`),
immediately before the actual snap build, to guarantee both run against
the same Python.

## CI tooling and docs

The tools that drive CI itself are pinned the same way, one level removed
from what actually ships:

- `pylock.ci.toml` - hash-pinned `hatch`, used by the lint
  (`python-package.yml`) and AppImage-build (`appimage-build.yml`)
  workflows to run `hatch run lint:check`/`hatch run appimage:build`.
  `python-publish.yml` doesn't need it - it builds directly via `pip
  wheel`/`python -m build` (see above), not through hatch.
- `pylock.docs.toml` - hash-pinned Sphinx toolchain
  (`doc/requirements.in`, the loose input spec), installed by Read the
  Docs (`.readthedocs.yaml`), `hatch run docs:build`, and
  `packaging/build-docs.sh` alike.

Installing from either needs pip >= 26.1 - older pip can't parse the
pylock.toml format at all and errors out trying to read it as a classic
requirements.txt. Every consumer pins pip to an exact version first
(`pip==<version>`) before touching either file.

Regenerate either with `pip lock`, e.g.:

```bash
pip lock "hatch==<version>" -o pylock.ci.toml
pip lock -r doc/requirements.in -o pylock.docs.toml
```

pip itself isn't hash-pinned - it comes from GitHub's or Read the Docs'
own managed build images, already-trusted infrastructure a hash pin on
pip wouldn't meaningfully add to.

PyPI publishing uses [Trusted
Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC via
`pypa/gh-action-pypi-publish`) - no long-lived token stored in the repo.

## Known limits / not covered here

- Snap builds are not covered — snapcraft's container-based build has no
  direct equivalent to `--build-constraint`/`SOURCE_DATE_EPOCH`, and
  achieving bit-identical snaps would be a separate effort.
- Neither reproducibility check runs on every push/PR the way appimage's
  own CI does - only automatically before a release, a deliberate
  trade-off to avoid the extra build cost on every push (see the release
  workflows for where each one is wired in).
