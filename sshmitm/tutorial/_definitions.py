"""Core data structures for the SSH-MITM tutorial system.

Writing a tutorial
------------------
Create a Python package (directory with ``__init__.py``) and place one
Markdown file per step alongside it.  The file name must match the step id::

    tutorials/my_tutorial/
        __init__.py   ← Tutorial subclass
        intro.md
        start-sshmitm.md
        intercept.md

Register via the ``sshmitm.Tutorial`` entry point::

    [project.entry-points."sshmitm.Tutorial"]
    my-tutorial = "mypkg.tutorials.my_tutorial:MyTutorial"

Minimal ``__init__.py``::

    from sshmitm.tutorial._definitions import Tutorial, Step
    from sshmitm.tutorial._conditions import PortOpen, UserInput
    from sshmitm.tutorial._client_actions import SSHPasswordAction

    class MyTutorial(Tutorial):
        id          = "01-my-tutorial"
        title       = "My Tutorial"
        category    = "Authentication"
        description = "Short description shown in the tutorial list."

        steps = [
            Step("intro", "What you will learn",
                 condition=Continue()),

            Step("start-sshmitm", "Start SSH-MITM",
                 condition=PortOpen("sshmitm_port"),
                 command="ssh-mitm server --remote-host 127.0.0.1 "
                         "--remote-port {mock_port} --listen-port {sshmitm_port}",
                 hint_waiting="Waiting for SSH-MITM on port {sshmitm_port}…",
                 hint_done="SSH-MITM is running. ✓"),

            Step("intercept", "Enter intercepted password",
                 condition=UserInput("password_value",
                                     prompt="Enter the password from the SSH-MITM terminal:"),
                 victim_action=SSHPasswordAction()),
        ]

Step content
------------
Each step's Markdown content is loaded from ``{step_id}.md`` in the same
directory as the tutorial's ``__init__.py``.  Inline *content* on a
:class:`Step` takes precedence if provided.

``{variable}`` placeholders in Markdown and command strings are substituted
at render time with values from the runtime credentials (ports, usernames,
passwords, …).
"""

from __future__ import annotations

import dataclasses
import importlib.resources
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from sshmitm.tutorial._conditions import Condition
    from sshmitm.tutorial._client_actions import ClientAction
    from sshmitm.tutorial._server_config import MockServerConfig


def _default_condition() -> "Condition":
    from sshmitm.tutorial._conditions import TRUE
    return TRUE()


@dataclasses.dataclass
class Step:
    """A single step in a tutorial.

    Parameters
    ----------
    id:
        Unique identifier within the tutorial.  Also used as the Markdown
        file name: ``{id}.md`` is loaded from the tutorial package directory
        when *content* is empty.
    title:
        Short label shown in the step list.
    content:
        Inline Markdown text.  Leave empty to load from ``{id}.md``.
        Supports ``{variable}`` placeholders.
    condition:
        Evaluated every 300 ms; the step completes when it returns *True*.
        Defaults to :class:`~sshmitm.tutorial._conditions.TRUE` (instant).
    victim_action:
        Automated client action started in a background thread when the step
        becomes active.  ``None`` means the step waits for the user or an
        external event without any automated traffic.
    command:
        Shell command shown as a copyable code block.  Supports
        ``{variable}`` placeholders.
    copyable:
        Credential keys displayed as individual copy-boxes (e.g.
        ``["password_value"]``).
    hint_waiting:
        Short text shown while the step is active but not yet complete.
    hint_done:
        Short text shown after the step has been completed.
    """

    id: str
    title: str
    content: str = ""
    condition: "Condition" = dataclasses.field(default_factory=_default_condition)
    victim_action: "ClientAction | None" = None
    command: str | None = None
    copyable: list[str] = dataclasses.field(default_factory=list)
    hint_waiting: str = ""
    hint_done: str = ""


class Tutorial:
    """Base class for SSH-MITM tutorials.

    Subclass this, set the class variables, and register via the
    ``sshmitm.Tutorial`` entry point.  See the module docstring for a
    complete example.

    Class variables
    ---------------
    id:
        Unique tutorial identifier (prefix with ``"01-"``, ``"02-"`` etc.
        to control display order).
    title:
        Display name shown in the sidebar.
    category:
        Groups tutorials (e.g. ``"Authentication"``).
    description:
        One-line summary shown in the tutorial list.
    server:
        :class:`~sshmitm.tutorial._server_config.MockServerConfig`.
        Defaults to a single user with an auto-generated password.
    steps:
        Ordered list of :class:`Step` objects.  Markdown content for each
        step is loaded automatically from ``{step.id}.md`` at instantiation.
    """

    id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    category: ClassVar[str] = "General"
    description: ClassVar[str] = ""

    # Subclasses set these as class variables.
    # `steps` is shadowed by an instance variable populated in __init__.
    steps: list[Step] = []

    def __init__(self) -> None:
        self.steps = self._load_steps()

    # ------------------------------------------------------------------
    # Step content loading
    # ------------------------------------------------------------------

    def _load_steps(self) -> list[Step]:
        """Return steps with Markdown content loaded via importlib.resources."""
        pkg = importlib.resources.files(self.__class__.__module__)
        result: list[Step] = []
        for step in self.__class__.steps:
            if step.content:
                result.append(step)
                continue
            try:
                content = pkg.joinpath(f"{step.id}.md").read_text(encoding="utf-8")
            except (FileNotFoundError, TypeError, OSError):
                content = ""
            result.append(
                dataclasses.replace(step, content=content) if content else step
            )
        return result

    # ------------------------------------------------------------------
    # Server config helpers
    # ------------------------------------------------------------------

    def get_server(self) -> "MockServerConfig":
        """Return the mock server config, falling back to the default."""
        from sshmitm.tutorial._server_config import MockServerConfig
        return getattr(self.__class__, "server", None) or MockServerConfig()

    @property
    def sshmitm_port(self) -> int:
        return self.get_server().sshmitm_port

    @property
    def mock_port(self) -> int:
        return self.get_server().mock_port
