"""Mock host: logfilegit.logfileinc.internal

Self-hosted Git platform (similar to Gitea/GitLab).  Publishes registered
SSH public keys at ``/<username>.keys`` without authentication — the same
pattern used by GitHub and GitLab.  Max Morgan has three keys registered.

The HTTP service is started via :meth:`start_services`, which launches
the built-in :class:`~sshmitm.tutorial.gitserver.GitServer`.  The session
data returned contains ``git_server_url`` and ``git_server_port`` so that
tutorial step templates can reference them.
"""
from __future__ import annotations

import asyncio
from typing import Any

import paramiko

from sshmitm.tutorial.hosts import Host, HTTPService, SSHService
from sshmitm.tutorial.hosts.logfile_inc import ApplicationServers, MaxMorgan


# ── Static git content for Logfile Inc. ───────────────────────────────────

_MMORGAN_REPOS = [
    {
        "name":        "dev-server-config",
        "description": "Internal server configuration and deployment scripts",
        "language":    "YAML",
        "visibility":  "internal",
        "updated":     "Updated 3 days ago",
        "commits": [
            ("Update SSH host keys after reinstall",        "mmorgan", "3 days ago"),
            ("Add Prometheus monitoring config",            "sking",   "1 week ago"),
            ("Add SSH config template (ForwardAgent yes)",  "lchen",   "3 weeks ago"),
            ("Initial commit",                              "mmorgan", "3 months ago"),
        ],
    },
    {
        "name":        "web-app",
        "description": "Customer portal (Django)",
        "language":    "Python",
        "visibility":  "internal",
        "updated":     "Updated 2 days ago",
        "commits": [
            ("Fix login redirect after session timeout", "mmorgan", "2 days ago"),
            ("Update Django to 4.2.9",                  "mmorgan", "5 days ago"),
            ("Add rate limiting middleware",             "mmorgan", "2 weeks ago"),
        ],
    },
    {
        "name":        "database-scripts",
        "description": "Backup and maintenance scripts",
        "language":    "Shell",
        "visibility":  "private",
        "updated":     "Updated 1 week ago",
        "commits": [
            ("Add weekly snapshot job", "mmorgan", "1 week ago"),
            ("Fix backup rotation",     "mmorgan", "3 weeks ago"),
        ],
    },
]


class LogfileGit(Host):
    """logfilegit.logfileinc.internal — self-hosted Git platform."""

    label    = "logfilegit"
    hostname = "logfilegit.logfileinc.internal"
    address  = "127.2.0.3"
    segment  = ApplicationServers
    users    = [MaxMorgan]
    services = [
        SSHService(port=20022, auth=["publickey"]),
        HTTPService(port=20443, tls=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        # Registered public keys per user: {username: [(comment, PKey), …]}
        self._public_keys: dict[str, list[tuple[str, paramiko.PKey]]] = {}
        self._git_server: Any = None

    def configure(self, session_data: dict) -> None:
        for user in self.__class__.users:
            reg_key = f"logfilegit_register_keys_{user.username}"
            if reg_key in session_data:
                self._public_keys[user.username] = list(session_data[reg_key])

    # ── service ──────────────────────────────────────────────────────────

    def start_services(self, session_data: dict) -> dict:
        """Start the HTTP git server and return ``git_server_url`` + ``git_server_port``."""
        from sshmitm.tutorial.gitserver import (
            GitCommit, GitRepo, GitServer, GitServerConfig, GitUser,
        )

        git_users = []
        for user in self.__class__.users:
            pubkeys = [
                f"{key.get_name()} {key.get_base64()} {comment}"
                for comment, key in self._public_keys.get(user.username, [])
            ]
            repos = []
            if user is MaxMorgan:
                for r in _MMORGAN_REPOS:
                    repos.append(GitRepo(
                        name        = r["name"],
                        description = r["description"],
                        language    = r["language"],
                        visibility  = r["visibility"],
                        updated     = r["updated"],
                        commits     = [
                            GitCommit(msg, author, ts)
                            for msg, author, ts in r["commits"]
                        ],
                    ))
            git_users.append(GitUser(
                username = user.username,
                fullname = user.full_name,
                bio      = f"{user.role} @ Logfile Inc.",
                pubkeys  = pubkeys,
                repos    = repos,
            ))

        config = GitServerConfig(brand="LogfileGit", users=git_users)
        srv = GitServer(config)
        srv.start()
        self._git_server = srv
        return {
            "git_server_port": srv.port,
            "git_server_url":  srv.url,
        }

    def stop_services(self) -> None:
        self._git_server = None

    # ── lifecycle ─────────────────────────────────────────────────────────

    async def start(self, events: asyncio.Queue) -> None:
        await super().start(events)

    async def stop(self) -> None:
        pass
