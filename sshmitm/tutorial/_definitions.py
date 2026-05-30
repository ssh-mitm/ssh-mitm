"""Data structures for the SSH-MITM tutorial system."""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class TutorialStep:
    """A single step within a tutorial.

    *content* is Markdown-formatted text rendered in the right panel.
    *condition* is a condition expression string evaluated by the runner,
    e.g. ``"TRUE()"``, ``"PORT_OPEN(sshmitm_port)"``,
    or ``'AUTH_EVENT("password", True)'``.
    *command* is an optional shell command shown as a copyable code block.
    *copyable* lists credential keys displayed as individual copy boxes.
    *hint_waiting* is shown while the step is active but not yet complete.
    *hint_done* is shown once the step has been completed.

    All string fields may use ``{variable}`` placeholders filled at render time.
    """

    id: str
    title: str
    content: str
    condition: str = "TRUE()"
    command: str | None = None
    copyable: list[str] = dataclasses.field(default_factory=list)
    hint_waiting: str = ""
    hint_done: str = ""
    auto_connect: bool = False
    input_prompt: str = ""


@dataclasses.dataclass
class Tutorial:
    """A complete tutorial consisting of ordered steps.

    *category* groups tutorials in the sidebar (e.g. ``"Authentication"``).
    *description* is a short summary shown in the tutorial list.
    """

    id: str
    title: str
    description: str
    category: str
    steps: list[TutorialStep]
    mock_port: int = 2200
    sshmitm_port: int = 10022
    auth_type: str = "password"
