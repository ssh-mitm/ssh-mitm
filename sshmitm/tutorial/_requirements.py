"""Requirement types that describe what a tutorial needs from the scenario.

Each :class:`Requirement` has two phases:

* :meth:`generate` — called once at session start; returns a dict of
  key → value entries merged into the global session data.
* :meth:`apply` — called after all ``generate()`` calls; configures
  host instances with the generated values.

Tutorials declare their requirements as a list; :class:`ScenarioGenerator`
executes them in order.
"""
from __future__ import annotations

import secrets
import random
import base64
import hashlib
from typing import TYPE_CHECKING

import paramiko

if TYPE_CHECKING:
    from sshmitm.tutorial.hosts import Host, User


class Requirement:
    """Base class for tutorial requirements."""

    def generate(self) -> dict:
        """Return key→value entries to add to the session data."""
        return {}

    def apply(self, hosts: dict[type[Host], Host], values: dict) -> None:
        """Configure host instances using the generated values."""


# ── Password requirements ───────────────────────────────────────────────────

class RandomPassword(Requirement):
    """Generate a random password for one user on one host.

    The generated password is stored under key
    ``"{host.label}_{user.username}_password"`` in the session data.
    """

    def __init__(self, user: type[User], host: type[Host]) -> None:
        self.user = user
        self.host = host
        self.key  = f"{host.label}_{user.username}_password"

    def generate(self) -> dict:
        return {self.key: secrets.token_hex(8)}

    def apply(self, hosts: dict[type[Host], Host], values: dict) -> None:
        host_inst = hosts.get(self.host)
        if host_inst:
            host_inst.configure({self.key: values[self.key]})


class StaticPassword(Requirement):
    """Use a fixed password for one user on one host.

    Useful when the tutorial text must reference a specific password.
    """

    def __init__(self, user: type[User], host: type[Host], password: str) -> None:
        self.user     = user
        self.host     = host
        self.password = password
        self.key      = f"{host.label}_{user.username}_password"

    def generate(self) -> dict:
        return {self.key: self.password}

    def apply(self, hosts: dict[type[Host], Host], values: dict) -> None:
        host_inst = hosts.get(self.host)
        if host_inst:
            host_inst.configure({self.key: values[self.key]})


# ── Key-pair requirements ───────────────────────────────────────────────────

class RandomKeyPair(Requirement):
    """Generate a fresh ECDSA key pair and optionally authorise it on hosts.

    Generated values stored in session data:

    * ``"keypair_{name}_private"`` — :class:`paramiko.ECDSAKey` instance
    * ``"keypair_{name}_fingerprint"`` — SHA-256 fingerprint string
      (``"SHA256:…"``)

    Parameters
    ----------
    user:
        The user this key belongs to.
    name:
        Short identifier unique within the tutorial (e.g. ``"sking_main"``).
    authorized_on:
        Hosts on which this key should be accepted.  Each host's
        :meth:`~sshmitm.tutorial.hosts.Host.configure` is called with
        ``{"authorize_key_{user.username}": key}``.
    """

    def __init__(
        self,
        user:          type[User],
        name:          str,
        authorized_on: list[type[Host]] | None = None,
    ) -> None:
        self.user          = user
        self.name          = name
        self.authorized_on = authorized_on or []
        self.key_private   = f"keypair_{name}_private"
        self.key_fp        = f"keypair_{name}_fingerprint"

    def generate(self) -> dict:
        key    = paramiko.ECDSAKey.generate()
        digest = hashlib.sha256(key.asbytes()).digest()
        fp     = "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode()
        return {
            self.key_private: key,
            self.key_fp:      fp,
        }

    def apply(self, hosts: dict[type[Host], Host], values: dict) -> None:
        key = values.get(self.key_private)
        if not key:
            return
        for host_cls in self.authorized_on:
            host_inst = hosts.get(host_cls)
            if host_inst:
                host_inst.configure({
                    f"authorize_key_{self.user.username}": key,
                })


class StaticKeyPair(Requirement):
    """Use an existing key pair.  The private key must be a paramiko PKey."""

    def __init__(
        self,
        user:          type[User],
        name:          str,
        key:           paramiko.PKey,
        authorized_on: list[type[Host]] | None = None,
    ) -> None:
        self.user          = user
        self.name          = name
        self._key          = key
        self.authorized_on = authorized_on or []
        self.key_private   = f"keypair_{name}_private"
        self.key_fp        = f"keypair_{name}_fingerprint"

    def generate(self) -> dict:
        digest = hashlib.sha256(self._key.asbytes()).digest()
        fp     = "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode()
        return {self.key_private: self._key, self.key_fp: fp}

    def apply(self, hosts: dict[type[Host], Host], values: dict) -> None:
        key = values.get(self.key_private)
        if not key:
            return
        for host_cls in self.authorized_on:
            host_inst = hosts.get(host_cls)
            if host_inst:
                host_inst.configure({
                    f"authorize_key_{self.user.username}": key,
                })


# ── Generic requirements ────────────────────────────────────────────────────

class RandomSecret(Requirement):
    """A random hex string not tied to any host, stored by name."""

    def __init__(self, name: str, length: int = 8) -> None:
        self.name   = name
        self.length = length

    def generate(self) -> dict:
        return {self.name: secrets.token_hex(self.length)}


class RandomChoice(Requirement):
    """Pick one value at random from *choices*, stored by name."""

    def __init__(self, name: str, choices: list) -> None:
        self.name    = name
        self.choices = choices

    def generate(self) -> dict:
        return {self.name: random.choice(self.choices)}


class StaticValue(Requirement):
    """Store a fixed value in the session data under *name*."""

    def __init__(self, name: str, value: object) -> None:
        self.name  = name
        self.value = value

    def generate(self) -> dict:
        return {self.name: self.value}


class NoneAuthAccess(Requirement):
    """Allow SSH ``none`` auth for *user* on *host* (no credential required).

    Used for CVE-2020-14145 simulations where the client connects with
    ``auth_none()`` to probe the server's fingerprint state.
    """

    def __init__(self, user: type[User], host: type[Host]) -> None:
        self.user = user
        self.host = host
        self.key  = f"{host.label}_{user.username}_none_auth"

    def generate(self) -> dict:
        return {self.key: True}

    def apply(self, hosts: dict[type[Host], Host], values: dict) -> None:
        host_inst = hosts.get(self.host)
        if host_inst:
            host_inst.configure({self.key: True})


class RegisterPublicKeys(Requirement):
    """Register named key pairs as public keys on a service host (e.g. LogfileGit).

    *entries* is a list of ``(comment, keypair_name)`` pairs.  Each
    ``keypair_name`` must match the *name* argument of a
    :class:`RandomKeyPair` / :class:`StaticKeyPair` requirement defined
    earlier in the same ``requires`` list.

    ``apply()`` reads the already-generated private keys from *values*
    and calls ``host.configure({"{host.label}_register_keys_{user.username}": [(comment, key)]})``
    so the host can build its service configuration (e.g. a ``/mmorgan.keys``
    endpoint on a Git platform).

    Example::

        requires = [
            RandomKeyPair(MaxMorgan, "mmorgan_web", authorized_on=[Web01]),
            RandomKeyPair(MaxMorgan, "mmorgan_old"),
            RegisterPublicKeys(MaxMorgan, LogfileGit, [
                ("mmorgan@laptop",     "mmorgan_web"),
                ("mmorgan@old-laptop", "mmorgan_old"),
            ]),
        ]
    """

    def __init__(
        self,
        user:    type[User],
        host:    type[Host],
        entries: list[tuple[str, str]],   # (comment, keypair_name)
    ) -> None:
        self.user    = user
        self.host    = host
        self.entries = entries

    def generate(self) -> dict:
        return {}

    def apply(self, hosts: dict[type[Host], Host], values: dict) -> None:
        host_inst = hosts.get(self.host)
        if not host_inst:
            return
        key_list = []
        for comment, keypair_name in self.entries:
            key = values.get(f"keypair_{keypair_name}_private")
            if key:
                key_list.append((comment, key))
        if key_list:
            host_inst.configure({
                f"logfilegit_register_keys_{self.user.username}": key_list
            })
