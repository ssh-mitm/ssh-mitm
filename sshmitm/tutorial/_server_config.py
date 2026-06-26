"""Mock server configuration for tutorial scenarios.

Example — common configurations::

    # Single user with auto-generated password (most tutorials)
    MockServerConfig()

    # Single user with public key auth
    MockServerConfig(users=[UserConfig(auth=PublicKeyAuth())])

    # Two users: one with no credentials, one with a password
    MockServerConfig(users=[
        UserConfig(auth=NoneAuth()),
        UserConfig(auth=PasswordAuth()),
    ])

    # Custom ports
    MockServerConfig(mock_port=2222, sshmitm_port=10022)

    # Keyboard-interactive (OTP simulation)
    from sshmitm.mockserver._interfaces import KbdintRound
    MockServerConfig(users=[UserConfig(auth=KeyboardInteractiveAuth(rounds=[
        KbdintRound(prompts=[("OTP Token: ", True)], answers=["123456"]),
    ]))])
"""

from __future__ import annotations

import dataclasses

import paramiko

from sshmitm.mockserver._interfaces import KbdintRound


@dataclasses.dataclass
class PasswordAuth:
    """Password authentication.

    ``password=None`` generates a random credential at tutorial start.
    The generated value is stored in ``credentials["password_value"]``.
    """
    password: str | None = None


@dataclasses.dataclass
class PublicKeyAuth:
    """Public key authentication.

    ``key=None`` generates a fresh ECDSA key pair at tutorial start.
    The generated key is stored internally; the fingerprint is available
    as ``credentials["pubkey_fingerprint"]``.
    """
    key: paramiko.PKey | None = None


@dataclasses.dataclass
class KeyboardInteractiveAuth:
    """Keyboard-interactive authentication with one or more challenge rounds.

    Each :class:`~sshmitm.mockserver._interfaces.KbdintRound` defines a set
    of prompts and the expected answers.  Multi-round sequences simulate MFA
    flows (e.g. OTP followed by a password).
    """
    rounds: list[KbdintRound] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class NoneAuth:
    """Accept the SSH ``none`` auth method (no credential required)."""


AuthConfig = PasswordAuth | PublicKeyAuth | KeyboardInteractiveAuth | NoneAuth


@dataclasses.dataclass
class UserConfig:
    """Configuration for a single mock-server user.

    ``username=None`` generates a random name at tutorial start.

    The credential key names written to the context depend on the auth type:

    * :class:`PasswordAuth`           → ``password_user``, ``password_value``
    * :class:`PublicKeyAuth`          → ``pubkey_user``, ``pubkey_fingerprint``
    * :class:`KeyboardInteractiveAuth`→ ``kbdint_user``
    * :class:`NoneAuth`               → ``none_user``

    For tutorials with multiple users of the same auth type, set an explicit
    *username* and reference it directly in your step content/commands.
    """
    username: str | None = None
    auth: AuthConfig = dataclasses.field(default_factory=PasswordAuth)


@dataclasses.dataclass
class MockServerConfig:
    """Full configuration for the tutorial mock SSH server.

    Defaults to a single user with an auto-generated password, which covers
    the majority of tutorial scenarios — most tutorials do not need to set
    this attribute at all.
    """
    users: list[UserConfig] = dataclasses.field(
        default_factory=lambda: [UserConfig()]
    )
    subsystems: list[str] = dataclasses.field(default_factory=lambda: ["sftp"])
    allow_shell: bool = True
    allow_exec: bool = True
    mock_port: int = 2200
    sshmitm_port: int = 10022


@dataclasses.dataclass
class TargetServerConfig:
    """Additional SSH server reachable directly (no MITM proxy).

    Used for lateral-movement targets probed with ``check-publickey`` or
    direct SSH connections.  Each target is started as an independent mock
    SSH server bound on its own port.

    Parameters
    ----------
    name:
        Short identifier (e.g. ``"web"``, ``"database"``).  The actual port
        is stored in the tutorial session data under the key
        ``"{name}_port"``.
    users:
        User accounts accepted by this target server.
    port:
        TCP port to listen on.  ``0`` lets the OS pick a free port.
    """
    name: str
    users: list[UserConfig] = dataclasses.field(default_factory=list)
    port: int = 0
