"""ScenarioSession and ScenarioGenerator.

A :class:`ScenarioSession` is the live state of one tutorial run: it holds
host instances, the asyncio event queue, and all generated session data.

:class:`ScenarioGenerator` takes a :class:`~sshmitm.tutorial.hosts.Scenario`,
a mapping of alias → host class, and a list of
:class:`~sshmitm.tutorial._requirements.Requirement` objects and produces a
fully configured :class:`ScenarioSession`.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sshmitm.tutorial.hosts import Host, Scenario, User
    from sshmitm.tutorial._events import Event
    from sshmitm.tutorial._requirements import Requirement


class ScenarioSession:
    """A running scenario instance for one tutorial session.

    Attributes
    ----------
    session_data:
        All generated values (passwords, key fingerprints, secrets, …).
    events:
        asyncio.Queue that receives :class:`~sshmitm.tutorial._events.Event`
        objects from mock hosts as the victim action runs.
    sshmitm_port:
        Port on which SSH-MITM listens for this session.
    """

    def __init__(
        self,
        hosts:        dict[str, Host],
        host_classes: dict[str, type[Host]],
        session_data: dict,
        sshmitm_port: int,
    ) -> None:
        self._hosts        = hosts
        self._host_classes = host_classes
        self.session_data  = session_data
        self.sshmitm_port  = sshmitm_port
        self.events: asyncio.Queue[Event] = asyncio.Queue()

    # ── credential accessors ────────────────────────────────────────────

    def credential(self, user: type[User], host: type[Host], kind: str) -> str:
        """Return ``session_data["{host.label}_{user.username}_{kind}"]``."""
        key = f"{host.label}_{user.username}_{kind}"
        return str(self.session_data.get(key, ""))

    def get_host(self, alias: str) -> Host:
        return self._hosts[alias]

    # ── template variable export ────────────────────────────────────────

    def template_vars(self) -> dict:
        """Return all variables available in step command/hint templates.

        Includes everything from *session_data* plus per-host convenience
        keys derived from the host class variables and service ports:

        * ``{alias}_address`` — host IP address
        * ``{alias}_hostname`` — host DNS name
        * ``{alias}_port`` — SSH/SFTP port (first SSH-like service found)
        * ``{alias}_port_{protocol.lower()}`` — port for each service
        * ``sshmitm_port``
        """
        vars: dict = dict(self.session_data)
        vars["sshmitm_port"] = self.sshmitm_port
        for alias, host in self._hosts.items():
            cls = host.__class__
            vars[f"{alias}_address"]  = cls.address
            vars[f"{alias}_hostname"] = cls.hostname
            ssh_svc = host.get_service("SSH") or host.get_service("SFTP")
            if ssh_svc:
                vars[f"{alias}_port"]     = ssh_svc.port
                vars[f"{alias}_port_ssh"] = ssh_svc.port
            for svc in cls.services:
                vars[f"{alias}_port_{svc.protocol.lower()}"] = svc.port
        return vars

    # ── lifecycle ───────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start all mock host services."""
        for host in self._hosts.values():
            await host.start(self.events)

    async def stop(self) -> None:
        """Stop all mock host services."""
        for host in self._hosts.values():
            await host.stop()


class ScenarioGenerator:
    """Build a :class:`ScenarioSession` from a scenario, aliases, and requirements.

    Usage::

        session = ScenarioGenerator.build(
            scenario     = LogfileIncScenario,
            host_aliases = {"proxy_target": Web01, "lateral": DB01},
            requires     = [
                RandomPassword(MaxMorgan, Web01),
                RandomKeyPair("sking_main", authorized_on=[Web01]),
            ],
            sshmitm_port = 10022,
        )
        await session.start()
    """

    @classmethod
    def build(
        cls,
        scenario:     type[Scenario] | None,
        host_aliases: dict[str, type[Host]],
        requires:     list[Requirement],
        sshmitm_port: int,
    ) -> ScenarioSession:
        # Instantiate each unique host class once.
        host_instances: dict[type[Host], Host] = {
            host_cls: host_cls()
            for host_cls in set(host_aliases.values())
        }

        # Generate all session data.
        session_data: dict = {}
        for req in requires:
            session_data.update(req.generate())

        # Apply requirements to host instances.
        for req in requires:
            req.apply(host_instances, session_data)

        # Map aliases → instances.
        alias_to_instance = {
            alias: host_instances[cls]
            for alias, cls in host_aliases.items()
        }

        return ScenarioSession(
            hosts        = alias_to_instance,
            host_classes = host_aliases,
            session_data = session_data,
            sshmitm_port = sshmitm_port,
        )
