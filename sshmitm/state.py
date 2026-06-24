"""
State directory resolution for ssh-mitm.

Supports all relevant Linux deployment variants:

  pip / pipx / uv / virtualenv / conda
    → $XDG_STATE_HOME/ssh-mitm/  (or ~/.local/state/ssh-mitm/)

  Snap (confined + classic)
    → Snap redirects $XDG_STATE_HOME to ~/snap/<name>/current/.local/state/
      automatically; no special handling required here.

  Flatpak
    → Flatpak redirects $XDG_STATE_HOME to ~/.var/app/<id>/.local/state/
      automatically; no special handling required here.

  AppImage
    → $APPIMAGE / $APPDIR are set but filesystem is the host's; standard
      XDG path is used.

  systemd system service  (StateDirectory=ssh-mitm)
    → $STATE_DIRECTORY=/var/lib/ssh-mitm  (takes priority over XDG)

  systemd user service
    → $STATE_DIRECTORY if set, else standard XDG path

  root without systemd
    → /var/lib/ssh-mitm/

  Distro packages (.deb / .rpm / Nix / Homebrew)
    → follow the same rules as pip depending on how the service is started

  Last resort (read-only filesystem, permission errors everywhere)
    → /tmp/ssh-mitm-<uid>/  (ephemeral, warns the caller)
"""

from __future__ import annotations

import logging
import os
from enum import Enum, auto
from pathlib import Path

log = logging.getLogger(__name__)


class DeploymentVariant(Enum):
    SNAP = auto()
    FLATPAK = auto()
    APPIMAGE = auto()
    SYSTEMD = auto()
    ROOT = auto()
    USER = auto()


def detect_deployment() -> DeploymentVariant:
    if os.environ.get("SNAP"):
        return DeploymentVariant.SNAP
    if os.environ.get("FLATPAK_ID"):
        return DeploymentVariant.FLATPAK
    if os.environ.get("APPIMAGE"):
        return DeploymentVariant.APPIMAGE
    if os.environ.get("STATE_DIRECTORY"):
        return DeploymentVariant.SYSTEMD
    if os.getuid() == 0:
        return DeploymentVariant.ROOT
    return DeploymentVariant.USER


def _candidates() -> list[Path]:
    result: list[Path] = []

    # 1. systemd StateDirectory — highest priority, directory already exists
    #    and is owned by the service user.  May be colon-separated.
    if state_dir := os.environ.get("STATE_DIRECTORY"):
        result.append(Path(state_dir.split(":")[0]))

    # 2. XDG_STATE_HOME — Snap and Flatpak redirect this env-var automatically
    #    so no special casing needed for either.
    if xdg := os.environ.get("XDG_STATE_HOME"):
        result.append(Path(xdg) / "ssh-mitm")

    # 3. Standard XDG fallback when XDG_STATE_HOME is not set
    if home := os.environ.get("HOME"):
        result.append(Path(home) / ".local" / "state" / "ssh-mitm")

    # 4. System-wide fallback for root without a home directory
    if os.getuid() == 0:
        result.append(Path("/var/lib/ssh-mitm"))

    # 5. Last resort: writable temp directory scoped to the current UID
    result.append(Path(f"/tmp/ssh-mitm-{os.getuid()}"))  # noqa: S108

    return result


def get_state_dir() -> Path | None:
    """
    Return a writable state directory, creating it if necessary.

    Logs a warning when falling back to /tmp and returns None only if every
    candidate path is unusable.
    """
    variant = detect_deployment()
    log.debug("deployment variant: %s", variant.name)

    for candidate in _candidates():
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError:
            log.debug("state dir candidate not creatable: %s", candidate)
            continue

        if os.access(candidate, os.W_OK):
            if str(candidate).startswith("/tmp/"):
                log.warning(
                    "no persistent state directory available, "
                    "using temporary path %s — host key will not survive restarts",
                    candidate,
                )
            else:
                log.debug("state dir: %s", candidate)
            return candidate

        log.debug("state dir candidate not writable: %s", candidate)

    log.error("could not find any writable state directory")
    return None
