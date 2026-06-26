"""Mock host: db01.logfileinc.internal

Production PostgreSQL database.  Not directly reachable from the developer
LAN — only web01 and files may connect.  There is no SSH service; db01 is an
indirect target reachable only via lateral movement through an already-
compromised application server.

The host declaration is included so that check-publickey can probe it for
key validity (CVE-2016-20012) without starting any interactive service.
"""
from __future__ import annotations

import asyncio

import paramiko

from sshmitm.tutorial.hosts import Host, PostgreSQLService
from sshmitm.tutorial.hosts.logfile_inc import DatabaseSegment, MaxMorgan, SarahKing


class DB01(Host):
    """db01.logfileinc.internal — production PostgreSQL database."""

    label    = "db01"
    hostname = "db01.logfileinc.internal"
    address  = "127.3.0.1"
    segment  = DatabaseSegment
    users    = [MaxMorgan, SarahKing]
    services = [
        PostgreSQLService(port=25432),
    ]

    def __init__(self) -> None:
        super().__init__()
        # SSH keys authorised for CVE-2016-20012 oracle probing
        self._authorized_keys: dict[str, list[paramiko.PKey]] = {}

    def configure(self, session_data: dict) -> None:
        for user in self.__class__.users:
            auth_key = f"authorize_key_{user.username}"
            if auth_key in session_data:
                self._authorized_keys.setdefault(user.username, []).append(
                    session_data[auth_key]
                )

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, events: asyncio.Queue) -> None:
        await super().start(events)

    async def stop(self) -> None:
        pass
