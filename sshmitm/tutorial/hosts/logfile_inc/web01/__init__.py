"""Mock host: web01.logfileinc.internal

Application server running the company's Django customer portal.
Accepts both password and public-key SSH authentication.
"""
from __future__ import annotations

import asyncio
import random

import paramiko

from sshmitm.tutorial.hosts import Host, HTTPService, SSHService
from sshmitm.tutorial.hosts.logfile_inc import (
    ApplicationServers,
    LisaChen,
    MaxMorgan,
    SarahKing,
)

_EXEC_OUTPUTS: dict[str, bytes] = {
    # Narrative anchor for Ch6: discovering LogfileGit
    "git clone git@logfilegit.logfileinc.internal:mmorgan/dev-server-config.git": (
        b"Cloning into 'dev-server-config'...\n"
        b"remote: Enumerating objects: 47, done.\n"
        b"remote: Counting objects: 100% (47/47), done.\n"
        b"remote: Compressing objects: 100% (31/31), done.\n"
        b"Receiving objects: 100% (47/47), 18.42 KiB | 3.68 MiB/s, done.\n"
        b"Resolving deltas: 100% (12/12), done.\n"
    ),
    # Reveals lchen's company-wide SSH config (ForwardAgent yes) — connects to Ch2
    "cat ~/.ssh/config": (
        b"# Logfile Inc. SSH config template\n"
        b"# Maintained by IT - lchen@logfileinc.internal\n"
        b"\n"
        b"Host *\n"
        b"    ForwardAgent yes\n"
        b"    ServerAliveInterval 60\n"
        b"    AddKeysToAgent yes\n"
        b"\n"
        b"Host web01\n"
        b"    HostName web01.logfileinc.internal\n"
        b"    User mmorgan\n"
        b"\n"
        b"Host files\n"
        b"    HostName files.logfileinc.internal\n"
        b"    User mmorgan\n"
    ),
}

EXEC_COMMANDS = list(_EXEC_OUTPUTS)


class Web01(Host):
    """web01.logfileinc.internal — application server, Django customer portal."""

    label    = "web01"
    hostname = "web01.logfileinc.internal"
    address  = "127.2.0.1"
    segment  = ApplicationServers
    users    = [MaxMorgan, SarahKing, LisaChen]
    services = [
        SSHService(port=20022, auth=["password", "publickey"]),
        HTTPService(port=20080),
        HTTPService(port=20443, tls=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._passwords: dict[str, str] = {}
        self._authorized_keys: dict[str, list[paramiko.PKey]] = {}
        self._exec_command: str | None = None

    def configure(self, session_data: dict) -> None:
        for user in self.__class__.users:
            pw_key   = f"web01_{user.username}_password"
            auth_key = f"authorize_key_{user.username}"
            if pw_key in session_data:
                self._passwords[user.username] = str(session_data[pw_key])
            if auth_key in session_data:
                self._authorized_keys.setdefault(user.username, []).append(
                    session_data[auth_key]
                )
        if "web01_exec_command" in session_data:
            self._exec_command = str(session_data["web01_exec_command"])

    # ── behavior ────────────────────────────────────────────────────────

    def random_exec_command(self) -> str:
        return random.choice(EXEC_COMMANDS)

    def exec_outputs(self, session_data: dict) -> dict[str, bytes]:
        cmd = str(session_data.get("web01_exec_command", ""))
        if not cmd:
            return {}
        output = _EXEC_OUTPUTS.get(cmd)
        return {cmd: output} if output else {}

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, events: asyncio.Queue) -> None:
        await super().start(events)

    async def stop(self) -> None:
        pass
