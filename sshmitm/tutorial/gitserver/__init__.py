"""Fake Git hosting server for SSH-MITM tutorials.

Exposes a GitLab-like web UI backed entirely by in-memory dataclasses.
No real git repositories are involved — the UI is purely cosmetic to create
a realistic phishing/credential-reuse scenario.

Usage::

    from sshmitm.tutorial.gitserver import GitServer, GitServerConfig, GitUser, GitRepo, GitCommit

    config = GitServerConfig(
        brand="CorpGit",
        users=[
            GitUser(
                username="alice",
                fullname="Alice Smith",
                bio="Backend engineer",
                pubkeys=["ssh-ed25519 AAAA... alice@workstation"],
                repos=[
                    GitRepo(
                        name="infra-scripts",
                        description="Internal infrastructure scripts",
                        language="Shell",
                        commits=[
                            GitCommit("Fix deploy pipeline", "alice", "2 days ago"),
                        ],
                    )
                ],
            )
        ],
    )
    srv = GitServer(config)
    srv.start()
    print(srv.url)
    # use srv.port, srv.url
"""

from __future__ import annotations

import dataclasses
import hashlib
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


@dataclasses.dataclass
class GitCommit:
    """A single (fake) commit entry shown in a repository's commit history.

    Parameters
    ----------
    message:
        Commit message shown in the UI.
    author:
        Author name or username.
    age:
        Human-readable age string, e.g. ``"3 days ago"``.
    sha:
        Hex SHA shown in the UI.  Auto-computed from *message* and *author*
        if left empty.
    """
    message: str
    author: str
    age: str
    sha: str = ""

    def __post_init__(self) -> None:
        if not self.sha:
            raw = f"{self.message}\x00{self.author}".encode()
            self.sha = hashlib.sha1(raw).hexdigest()[:7]  # noqa: S324


@dataclasses.dataclass
class GitRepo:
    """A fake repository listed on a user's profile page.

    Parameters
    ----------
    name:
        Repository slug (used in the URL ``/{username}/{name}``).
    description:
        One-line summary shown on the profile card.
    language:
        Primary language badge (e.g. ``"Python"``).
    visibility:
        ``"public"``, ``"internal"``, or ``"private"``.
    stars:
        Star count shown on the card.
    forks:
        Fork count shown on the card.
    updated:
        Human-readable last-update string, e.g. ``"Updated 3 days ago"``.
    commits:
        Ordered list of :class:`GitCommit` objects shown on the repo page
        (most recent first).
    """
    name: str
    description: str = ""
    language: str = ""
    visibility: str = "public"
    stars: int = 0
    forks: int = 0
    updated: str = ""
    commits: list[GitCommit] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class GitUser:
    """A fake user account hosted on the :class:`GitServer`.

    Parameters
    ----------
    username:
        URL-safe username (used in ``/{username}``).
    fullname:
        Display name shown on the profile page.
    bio:
        Short biography line.
    pubkeys:
        Raw SSH public key lines (``"ssh-ed25519 AAAA... comment"``).
        Accessible at ``/{username}.keys``.
    repos:
        Repositories owned by this user.
    """
    username: str
    fullname: str = ""
    bio: str = ""
    pubkeys: list[str] = dataclasses.field(default_factory=list)
    repos: list[GitRepo] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class GitServerConfig:
    """Top-level configuration for a :class:`GitServer` instance.

    Parameters
    ----------
    users:
        All user accounts hosted on this server.
    brand:
        Site name shown in the navigation bar (e.g. ``"LogfileGit"``).
    port:
        TCP port to bind on.  ``0`` lets the OS pick a free port.
    """
    users: list[GitUser] = dataclasses.field(default_factory=list)
    brand: str = "LogfileGit"
    port: int = 0


class GitServer:
    """Fake Git-hosting HTTP server.

    Starts an :mod:`aiohttp` application in a background daemon thread.
    The server is ready when :meth:`start` returns.

    Parameters
    ----------
    config:
        :class:`GitServerConfig` describing the hosted content.

    Example::

        srv = GitServer(config)
        srv.start()
        print(srv.url)      # "http://127.0.0.1:54321"
        print(srv.port)     # 54321
    """

    def __init__(self, config: GitServerConfig) -> None:
        self._config = config
        self._port: int = 0
        self._ready = threading.Event()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def port(self) -> int:
        """Actual TCP port the server is listening on."""
        return self._port

    @property
    def url(self) -> str:
        """Base URL of the server (``http://127.0.0.1:{port}``)."""
        return f"http://127.0.0.1:{self._port}"

    def start(self) -> None:
        """Start the server in a background daemon thread and block until ready."""
        t = threading.Thread(target=self._run, daemon=True)
        t.start()
        self._ready.wait(timeout=5.0)

    def stop(self) -> None:
        """No-op: the server runs in a daemon thread and exits with the process."""

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run(self) -> None:
        import asyncio
        from sshmitm.tutorial.gitserver._server import make_app

        async def _main() -> None:
            from aiohttp import web
            app = make_app(self._config)
            runner = web.AppRunner(app, access_log=None)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", self._config.port)
            await site.start()
            self._port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
            self._ready.set()
            await asyncio.Event().wait()

        asyncio.run(_main())
