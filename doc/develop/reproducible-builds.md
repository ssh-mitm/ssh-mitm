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

## Known limits / not covered here

- The AppImage build (`sshmitm-x86_64.AppImage`) goes through the
  separate [`appimage`](https://github.com/ssh-mitm/appimage) package,
  which handles its own reproducibility concerns independently of this
  page.
- Snap builds are not covered — snapcraft's container-based build has no
  direct equivalent to `--build-constraint`/`SOURCE_DATE_EPOCH`, and
  achieving bit-identical snaps would be a separate effort.
- The runtime dependency set (`requirements.txt`) is version-pinned but
  not hash-pinned — that affects the wheel's `Requires-Dist` metadata,
  not the wheel bytes themselves, and is out of scope here.
- CI does not yet run `verify-reproducible-build.sh` as part of the
  release workflow (`python-publish.yml`). Wiring it in is planned
  alongside a move to [Trusted
  Publishing](https://docs.pypi.org/trusted-publishers/), which replaces
  the long-lived `TWINE_PASSWORD` token currently used there.
