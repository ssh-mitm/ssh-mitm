"""Load tutorial definitions from TOML + Markdown directory bundles."""

from __future__ import annotations

import tomllib
from importlib import resources
from importlib.resources.abc import Traversable

from sshmitm.tutorial._definitions import EventAlert, Tutorial, TutorialStep


def _read_step_content(tutorial_dir: Traversable, step_id: str) -> str:
    md = tutorial_dir.joinpath(f"{step_id}.md")
    try:
        return md.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return ""


def _load_dir(tutorial_dir: Traversable) -> Tutorial:
    toml_file = tutorial_dir.joinpath("tutorial.toml")
    data = tomllib.loads(toml_file.read_text(encoding="utf-8"))

    steps = [
        TutorialStep(
            id=s["id"],
            title=s["title"],
            content=_read_step_content(tutorial_dir, s["id"]),
            condition=s.get("condition", "TRUE()"),
            command=s.get("command"),
            copyable=s.get("copyable", []),
            hint_waiting=s.get("hint_waiting", ""),
            hint_done=s.get("hint_done", ""),
            auto_connect=bool(s.get("auto_connect", False)),
            input_prompt=s.get("input_prompt", ""),
        )
        for s in data.get("steps", [])
    ]

    event_alerts = [
        EventAlert(
            event=a["event"],
            title=a.get("title", ""),
            detail=a.get("detail", ""),
            hint=a.get("hint", ""),
        )
        for a in data.get("event_alerts", [])
    ]

    return Tutorial(
        id=data["id"],
        title=data["title"],
        description=data.get("description", ""),
        category=data.get("category", "General"),
        steps=steps,
        mock_port=int(data.get("mock_port", 2200)),
        sshmitm_port=int(data.get("sshmitm_port", 10022)),
        auth_type=data.get("auth_type", "password"),
        event_alerts=event_alerts,
    )


def load_all(package: str) -> list[Tutorial]:
    """Load all tutorials from subdirectories of *package* in definition order.

    A subdirectory is recognised as a tutorial if it contains a
    ``tutorial.toml`` file.  Directories are processed in alphabetical order;
    prefix directory names with numbers (e.g. ``01-password-auth/``) to
    control the display order.
    """
    root = resources.files(package)
    tutorials: list[Tutorial] = []
    for entry in sorted(root.iterdir(), key=lambda e: e.name):
        try:
            toml_file = entry.joinpath("tutorial.toml")
            toml_file.read_text(encoding="utf-8")  # existence check
        except (FileNotFoundError, OSError, TypeError):
            continue
        tutorials.append(_load_dir(entry))
    return tutorials
