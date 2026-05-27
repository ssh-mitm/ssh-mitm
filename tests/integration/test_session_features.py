"""Integration tests for SSH session features: terminal modes and signal forwarding.

Stack:
  paramiko client
    ↓  connects with PTY + custom modes / sends signal
  ssh-mitm (subprocess)
    ↓  forwards PTY modes via request_pty_with_modes()
    ↓  forwards signals via check_channel_signal_request() + send_signal()
  _RecordingServerInterface (paramiko, in-process)
    records pty_modes and received signals for assertions
"""

from __future__ import annotations

import struct
import time

import paramiko
import pytest

from sshmitm.workarounds.channel import request_pty_with_modes, send_signal

_PASSWORD = "testpass"
_USERNAME = "testuser"

# Minimal non-trivial terminal modes: VINTR=3, ECHO=0, TTY_OP_END
# RFC 4254 §8: each entry is opcode(1 byte) + value(uint32 big-endian)
_TEST_MODES = (
    struct.pack(">BI", 1, 3)    # VINTR = 3
    + struct.pack(">BI", 53, 0) # ECHO  = 0 (echo off)
    + b"\x00"                   # TTY_OP_END
)


def _open_shell_via_mitm(
    mitm_port: int,
    modes: bytes = b"",
) -> tuple[paramiko.Transport, paramiko.Channel]:
    """Connect to the MITM, authenticate with password, and open a shell channel.

    Returns (transport, channel) with PTY requested using *modes*.
    """
    t = paramiko.Transport(("127.0.0.1", mitm_port))
    t.start_client(timeout=10)
    t.auth_password(_USERNAME, _PASSWORD)
    chan = t.open_session(timeout=10)
    request_pty_with_modes(chan, b"xterm", 80, 24, 0, 0, modes=modes)
    chan.invoke_shell()
    return t, chan


def test_pty_modes_forwarded(mitm_recording: tuple[int, object]) -> None:
    """Terminal modes sent by the client are forwarded unchanged to the remote server."""
    mitm_port, iface = mitm_recording  # type: ignore[misc]

    t, chan = _open_shell_via_mitm(mitm_port, modes=_TEST_MODES)
    try:
        # Give the MITM time to establish the upstream connection and request PTY
        deadline = time.monotonic() + 5
        while iface.pty_modes is None and time.monotonic() < deadline:  # type: ignore[attr-defined]
            time.sleep(0.05)

        assert iface.pty_modes == _TEST_MODES, (  # type: ignore[attr-defined]
            f"Expected modes {_TEST_MODES!r}, got {iface.pty_modes!r}"  # type: ignore[attr-defined]
        )
    finally:
        chan.close()
        t.close()


def test_signal_forwarded(mitm_recording: tuple[int, object]) -> None:
    """A signal sent by the client is forwarded to the remote server."""
    mitm_port, iface = mitm_recording  # type: ignore[misc]

    t, chan = _open_shell_via_mitm(mitm_port)
    try:
        # Wait for the shell prompt so the remote session is fully established
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if chan.recv_ready():
                chan.recv(256)
                break
            time.sleep(0.05)

        # Send TERM signal through the MITM to the remote server
        send_signal(chan, "TERM")

        # Wait for the recording target to receive it
        deadline = time.monotonic() + 5
        while not iface.signals and time.monotonic() < deadline:  # type: ignore[attr-defined]
            time.sleep(0.05)

        assert "TERM" in iface.signals, (  # type: ignore[attr-defined]
            f"Expected TERM signal, got {iface.signals!r}"  # type: ignore[attr-defined]
        )
    finally:
        chan.close()
        t.close()
