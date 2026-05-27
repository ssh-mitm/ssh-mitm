"""Integration tests for none authentication passthrough.

Stack:
  paramiko client (none auth)
    ↓  check_auth_none → AUTH_SUCCESSFUL
  ssh-mitm (subprocess)
    ↓  auto-detects "none" from banner probe, passes through to mock target
  Mock SSH target (paramiko, in-process, none-auth only)
"""

from __future__ import annotations

import paramiko
import pytest


def _connect_none_auth(port: int, username: str = "testuser") -> paramiko.Transport:
    """Open a paramiko transport to *port* and authenticate with none auth."""
    t = paramiko.Transport(("127.0.0.1", port))
    t.start_client(timeout=10)
    remaining = t.auth_none(username)
    if remaining:
        t.close()
        pytest.fail(f"none auth not accepted; remaining methods: {remaining}")
    return t


def test_none_auth_passthrough(mitm_none_auth: int) -> None:
    """None auth is accepted by MITM and passed through to the remote server."""
    t = _connect_none_auth(mitm_none_auth)
    try:
        assert t.is_authenticated(), "Transport should be authenticated after auth_none"
    finally:
        t.close()


def test_none_auth_exec(mitm_none_auth: int) -> None:
    """After none auth through MITM an exec channel works end-to-end."""
    t = _connect_none_auth(mitm_none_auth)
    try:
        chan = t.open_session(timeout=10)
        chan.exec_command("echo integration-test")
        output = b""
        while True:
            chunk = chan.recv(256)
            if not chunk:
                break
            output += chunk
        chan.close()
        assert b"REMOTE_OK" in output, f"Unexpected output: {output!r}"
    finally:
        t.close()
