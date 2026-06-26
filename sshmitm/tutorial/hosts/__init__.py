"""Base classes for scenario assets: users, segments, services, hosts, scenarios."""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from sshmitm.tutorial._events import Event


# ── Users ──────────────────────────────────────────────────────────────────

class User:
    """A person who appears in the scenario."""
    username:  ClassVar[str] = ""
    full_name: ClassVar[str] = ""
    role:      ClassVar[str] = ""


# ── Segments ───────────────────────────────────────────────────────────────

class Segment:
    """A network segment in the lab topology."""
    name:   ClassVar[str] = ""
    subnet: ClassVar[str] = ""


# ── Services ───────────────────────────────────────────────────────────────

class Service:
    """A single network service on a host."""
    protocol: ClassVar[str] = ""

    def __init__(self, port: int) -> None:
        self.port = port


class SSHService(Service):
    protocol = "SSH"

    def __init__(self, port: int, auth: list[str] | None = None) -> None:
        super().__init__(port)
        self.auth = auth or ["password", "publickey"]


class SFTPService(Service):
    protocol = "SFTP"

    def __init__(self, port: int) -> None:
        super().__init__(port)


class HTTPService(Service):
    protocol = "HTTP"

    def __init__(self, port: int, tls: bool = False) -> None:
        super().__init__(port)
        self.tls = tls
        if tls:
            self.protocol = "HTTPS"


class SNMPService(Service):
    protocol = "SNMP"

    def __init__(self, port: int) -> None:
        super().__init__(port)


class PostgreSQLService(Service):
    protocol = "PostgreSQL"

    def __init__(self, port: int) -> None:
        super().__init__(port)


# ── Host ───────────────────────────────────────────────────────────────────

class Host:
    """A mock server in the scenario.

    Subclass this for each host in the lab.  Set class variables to describe
    the host; override :meth:`configure`, :meth:`start`, and :meth:`stop` to
    provide mock behaviour.
    """
    label:    ClassVar[str] = ""
    hostname: ClassVar[str] = ""
    address:  ClassVar[str] = ""
    segment:  ClassVar[type[Segment] | None] = None
    users:    ClassVar[list[type[User]]] = []
    services: ClassVar[list[Service]] = []

    def __init__(self) -> None:
        self._events: asyncio.Queue[Event] | None = None

    # ── service lookup ──────────────────────────────────────────────────

    def get_service(self, protocol: str) -> Service | None:
        for svc in self.__class__.services:
            if svc.protocol.upper() == protocol.upper():
                return svc
        return None

    @property
    def port_ssh(self) -> int | None:
        svc = self.get_service("SSH") or self.get_service("SFTP")
        return svc.port if svc else None

    # ── lifecycle ───────────────────────────────────────────────────────

    def configure(self, session_data: dict) -> None:
        """Inject session values (passwords, keys, secrets) before start."""

    async def start(self, events: asyncio.Queue[Event]) -> None:
        """Start mock services.  Store the event queue for later use."""
        self._events = events

    async def stop(self) -> None:
        """Stop all running mock services."""

    # ── helpers ─────────────────────────────────────────────────────────

    # ── additional services (non-SSH) ──────────────────────────────────

    def start_services(self, session_data: dict) -> dict:
        """Start any non-SSH services (HTTP, Git, SNMP, …) for this host.

        Called synchronously by the runner.  Returns additional session
        data to merge (e.g. ``{"git_server_url": "http://…"}``) so that
        step command/hint templates can reference it.

        Override in hosts that run supplemental services alongside SSH.
        """
        return {}

    def stop_services(self) -> None:
        """Stop any services started by :meth:`start_services`."""

    # ── event helper ───────────────────────────────────────────────────

    async def _emit(self, event: Event) -> None:
        if self._events is not None:
            await self._events.put(event)


# ── Scenario ───────────────────────────────────────────────────────────────

class Scenario:
    """Groups the hosts and users that belong to one assessment scenario."""
    name:  ClassVar[str] = ""
    users: ClassVar[list[type[User]]] = []
    hosts: ClassVar[list[type[Host]]] = []
