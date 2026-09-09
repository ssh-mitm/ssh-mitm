# Reproducible Wheel Builds

The wheel published to [pypi.org](https://pypi.org/project/ssh-mitm/) is
built via `hatch build`, using `hatchling` and `hatch-requirements-txt` as
the PEP 518 build backend (`[build-system]` in `pyproject.toml`). This
page covers how that build is made hash-verified and provably
bit-identical across independent builds of the same commit.

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
slow for the everyday dev loop. Run it as a pre-release check instead.

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

To confirm the AppImage build is itself bit-identical, build it twice from
a clean `build/` directory and compare hashes, the same idea as
`verify-reproducible-build.sh` above but for the AppImage instead of the
wheel:

```bash
rm -rf build && hatch run appimage:build && sha256sum dist/ssh-mitm-x86_64.AppImage
```

## Known limits / not covered here

- Snap builds are not covered — snapcraft's container-based build has no
  direct equivalent to `--build-constraint`/`SOURCE_DATE_EPOCH`, and
  achieving bit-identical snaps would be a separate effort.
- CI does not yet run `verify-reproducible-build.sh` as part of the
  release workflow (`python-publish.yml`). Wiring it in is planned
  alongside a move to [Trusted
  Publishing](https://docs.pypi.org/trusted-publishers/), which replaces
  the long-lived `TWINE_PASSWORD` token currently used there.
