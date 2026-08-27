"""Mock host: db01.logfileinc.internal

Production PostgreSQL database.  Not directly reachable from the developer
LAN — only web01 and files may connect.  There is no SSH service; db01 is an
indirect target reachable only via lateral movement through an already-
compromised application server.

The host declaration is included so that check-publickey can probe it for
key validity (CVE-2016-20012) without starting any interactive service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

import paramiko

from sshmitm.tutorial.hosts import Host, PostgreSQLService, Service, User
from sshmitm.tutorial.hosts.logfile_inc import DatabaseSegment, MaxMorgan, SarahKing

if TYPE_CHECKING:
    import asyncio

    from sshmitm.tutorial._events import Event


class DB01(Host):
    """db01.logfileinc.internal — production PostgreSQL database."""

    label = "db01"
    hostname = "db01.logfileinc.internal"
    address = "127.3.0.1"
    segment = DatabaseSegment
    users: ClassVar[list[type[User]]] = [MaxMorgan, SarahKing]
    services: ClassVar[list[Service]] = [
        PostgreSQLService(port=25432),
    ]

    def __init__(self) -> None:
        super().__init__()
        # SSH keys authorised for CVE-2016-20012 oracle probing
        self._authorized_keys: dict[str, list[paramiko.PKey]] = {}

    def configure(self, session_data: dict[str, object]) -> None:
        for user in self.__class__.users:
            auth_key = f"authorize_key_{user.username}"
            key = session_data.get(auth_key)
            if isinstance(key, paramiko.PKey):
                self._authorized_keys.setdefault(user.username, []).append(key)

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, events: asyncio.Queue[Event]) -> None:
        await super().start(events)

    async def stop(self) -> None:
        pass
