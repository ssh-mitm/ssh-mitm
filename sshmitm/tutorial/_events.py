"""Event types emitted by mock hosts during a tutorial session."""
from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sshmitm.tutorial.hosts import Host, User


@dataclasses.dataclass
class AuthEvent:
    """A mock server authentication attempt."""
    user:       type[User]
    host:       type[Host]
    method:     str           # "password" | "publickey" | "none" | "keyboard-interactive"
    success:    bool
    credential: str = ""      # password text or key fingerprint


@dataclasses.dataclass
class FileTransferEvent:
    """An SFTP file transfer on a mock server."""
    user:      type[User]
    host:      type[Host]
    path:      str
    direction: str            # "download" | "upload"
    content:   bytes = b""


@dataclasses.dataclass
class ExecEvent:
    """A non-interactive SSH exec command on a mock server."""
    user:    type[User]
    host:    type[Host]
    command: str
    output:  bytes = b""


@dataclasses.dataclass
class SessionEvent:
    """SSH session opened or closed on a mock server."""
    user:        type[User]
    host:        type[Host]
    event_type:  str          # "opened" | "closed"
    mirror_port: int | None = None


@dataclasses.dataclass
class FingerprintEvent:
    """SSH host-key fingerprint check by a client."""
    user:           type[User]
    host:           type[Host]
    state:          str        # "new" | "cached"
    preferred_algo: str = ""


Event = AuthEvent | FileTransferEvent | ExecEvent | SessionEvent | FingerprintEvent
