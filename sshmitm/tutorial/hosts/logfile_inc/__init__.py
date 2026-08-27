"""Logfile Inc. — the scenario used by all interactive tutorial chapters.

Defines users, network segments, and the scenario class.  Individual host
modules live in sub-packages of this package.
"""

from __future__ import annotations

from typing import ClassVar

from sshmitm.tutorial.hosts import Host, Scenario, Segment, User

# ── Users ──────────────────────────────────────────────────────────────────


class MaxMorgan(User):
    username = "mmorgan"
    full_name = "Max Morgan"
    role = "Developer"


class SarahKing(User):
    username = "sking"
    full_name = "Sarah King"
    role = "DevOps Engineer"


class LisaChen(User):
    username = "lchen"
    full_name = "Lisa Chen"
    role = "IT Manager"


class ThomasWebb(User):
    username = "twebb"
    full_name = "Thomas Webb"
    role = "Network Administrator"


# ── Segments ───────────────────────────────────────────────────────────────


class DeveloperLAN(Segment):
    name = "Developer LAN"
    subnet = "127.1.0.0/24"


class ApplicationServers(Segment):
    name = "Application servers"
    subnet = "127.2.0.0/24"


class DatabaseSegment(Segment):
    name = "Database"
    subnet = "127.3.0.0/24"


class ManagementSegment(Segment):
    name = "Management"
    subnet = "127.4.0.0/24"


# ── Scenario ───────────────────────────────────────────────────────────────


class LogfileIncScenario(Scenario):
    """All tutorial chapters are set within this authorized assessment."""

    name = "Logfile Inc."
    users: ClassVar[list[type[User]]] = [MaxMorgan, SarahKing, LisaChen, ThomasWebb]

    @classmethod
    def all_hosts(cls) -> list[type[Host]]:
        # Local imports: these host modules import back from this module
        # (users/segments above), so importing them at module level here
        # would create a circular import.
        # pylint: disable=import-outside-toplevel
        from sshmitm.tutorial.hosts.logfile_inc.db01 import DB01  # noqa: PLC0415
        from sshmitm.tutorial.hosts.logfile_inc.files import Files  # noqa: PLC0415
        from sshmitm.tutorial.hosts.logfile_inc.logfilegit import (  # noqa: PLC0415
            LogfileGit,
        )
        from sshmitm.tutorial.hosts.logfile_inc.router01 import (  # noqa: PLC0415
            Router01,
        )
        from sshmitm.tutorial.hosts.logfile_inc.web01 import Web01  # noqa: PLC0415

        return [Web01, Files, Router01, LogfileGit, DB01]
