"""Persists tutorial completion state to ~/.config/ssh-mitm/tutorial_progress.json."""

from __future__ import annotations

import json
from pathlib import Path

_CONFIG_DIR = Path.home() / ".config" / "ssh-mitm"
_PROGRESS_FILE = _CONFIG_DIR / "tutorial_progress.json"


def load_completed() -> set[str]:
    if not _PROGRESS_FILE.exists():
        return set()
    try:
        data = json.loads(_PROGRESS_FILE.read_text())
        return set(data.get("completed", []))
    except (json.JSONDecodeError, OSError):
        return set()


def mark_completed(tutorial_id: str) -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    completed = load_completed()
    completed.add(tutorial_id)
    _PROGRESS_FILE.write_text(
        json.dumps({"completed": sorted(completed)}, indent=2)
    )


def reset_completed(tutorial_id: str) -> None:
    completed = load_completed()
    completed.discard(tutorial_id)
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _PROGRESS_FILE.write_text(
        json.dumps({"completed": sorted(completed)}, indent=2)
    )
