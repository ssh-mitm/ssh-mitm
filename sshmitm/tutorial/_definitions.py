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

    from sshmitm.tutorial._definitions import Step, Tutorial
    from sshmitm.tutorial._conditions import PortOpen, UserInput, TRUE
    from sshmitm.tutorial._requirements import RandomPassword
    from sshmitm.tutorial.hosts.logfile_inc import LogfileIncScenario, MaxMorgan
    from sshmitm.tutorial.hosts.logfile_inc.web01 import Web01

    class MyTutorial(Tutorial):
        id          = "01-my-tutorial"
        title       = "My Tutorial"
        category    = "Authentication"
        description = "Short description shown in the tutorial list."

        scenario     = LogfileIncScenario
        proxy_target = Web01
        victim       = MaxMorgan
        requires     = [RandomPassword(MaxMorgan, Web01)]

        steps = [
            Step("intro", "What you will learn", condition=TRUE()),

            Step("start-sshmitm", "Start SSH-MITM",
                 condition=PortOpen("sshmitm_port"),
                 command="ssh-mitm server"
                         " --remote-host {proxy_target_address}"
                         " --remote-port {proxy_target_port}"
                         " --listen-port {sshmitm_port}"),

            Step("intercept", "Enter intercepted password",
                 condition=UserInput("web01_mmorgan_password",
                                     prompt="Enter the password from the SSH-MITM terminal:")),
        ]

Step content
------------
Each step's Markdown content is loaded from ``{step_id}.md`` in the same
directory as the tutorial's ``__init__.py``.  Inline *content* on a
:class:`Step` takes precedence if provided.

``{variable}`` placeholders in Markdown and command strings are substituted
at render time with values from :meth:`ScenarioSession.template_vars`.
"""

from __future__ import annotations

import dataclasses
import importlib.resources
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from sshmitm.tutorial._conditions import Condition
    from sshmitm.tutorial._client_actions import ClientAction
    from sshmitm.tutorial._requirements import Requirement
    from sshmitm.tutorial.hosts import Host, Scenario, User
    from sshmitm.tutorial.gitserver import GitServerConfig


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
        becomes active.
    command:
        Shell command shown as a copyable code block.
    copyable:
        Credential keys displayed as individual copy-boxes.
    hint_waiting:
        Short text shown while the step is active but not yet complete.
    hint_done:
        Short text shown after the step has been completed.
    """

    id:            str
    title:         str
    content:       str = ""
    condition:     "Condition" = dataclasses.field(default_factory=_default_condition)
    victim_action: "ClientAction | None" = None
    command:       str | None = None
    copyable:      list[str] = dataclasses.field(default_factory=list)
    hint_waiting:  str = ""
    hint_done:     str = ""


class Tutorial:
    """Base class for SSH-MITM tutorials.

    Subclass this, set the class variables, and register via the
    ``sshmitm.Tutorial`` entry point.

    Scenario API
    ------------
    scenario:
        The :class:`~sshmitm.tutorial.hosts.Scenario` this tutorial belongs
        to.  Used for documentation and consistency checks.
    proxy_target:
        The :class:`~sshmitm.tutorial.hosts.Host` SSH-MITM connects to as
        its backend.  The runner starts a mock SSH server for this host.
        ``None`` for tutorials that only use direct connections (e.g.
        ``check-publickey``).
    victim:
        The :class:`~sshmitm.tutorial.hosts.User` whose client the victim
        action impersonates.  The runner bridges legacy credential keys
        (``password_user``, ``_client_key``, etc.) from this user.
    requires:
        Ordered list of :class:`~sshmitm.tutorial._requirements.Requirement`
        objects that generate session data (passwords, key pairs, secrets)
        and configure host instances.
    direct_targets:
        Additional hosts started as standalone SSH mock servers for direct
        connections (not via SSH-MITM).  Alias → host class.  The runner
        sets ``session_data["{alias}_port"]`` after startup.
    sshmitm_port:
        Port SSH-MITM listens on for this tutorial (default: 10022).
    lab_service_labels:
        Maps session-data keys to human-readable labels for the web UI
        (e.g. ``{"mock_port": "web01.logfileinc.internal"}``).
    """

    id:          ClassVar[str] = ""
    title:       ClassVar[str] = ""
    category:    ClassVar[str] = "General"
    description: ClassVar[str] = ""
    tags:        ClassVar[list[str]] = []
    docs:        ClassVar[dict[str, str]] = {}

    # ── Scenario API ───────────────────────────────────────────────────

    scenario:       ClassVar[type[Scenario] | None] = None
    proxy_target:   ClassVar[type[Host] | None] = None
    victim:         ClassVar[type[User] | None] = None
    requires:       ClassVar[list[Requirement]] = []
    direct_targets: ClassVar[dict[str, type[Host]]] = {}
    sshmitm_port:   ClassVar[int] = 10022

    lab_service_labels: ClassVar[dict[str, str]] = {}

    # ── Steps ──────────────────────────────────────────────────────────

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
    # Optional overrides
    # ------------------------------------------------------------------

    def generate_tutorial_session_data(self) -> dict:
        """Return extra session data merged in after :class:`ScenarioGenerator`.

        Override to inject values not covered by *requires* — for example
        a dynamic choice where the tutorial needs explicit control over the
        session-data key name.
        """
        return {}

    def get_git_server(self, session_data: dict) -> "GitServerConfig | None":
        """Return a git server config built from *session_data*, or ``None``.

        Transitional hook: override in tutorials that need a standalone git
        server not yet modelled as a :class:`~sshmitm.tutorial.hosts.Host`.
        Prefer implementing git functionality in the host's
        :meth:`~sshmitm.tutorial.hosts.Host.start_services` instead.
        """
        return None
