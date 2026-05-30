"""Fixtures for integration tests.

No external SSH infrastructure required:
- Mock SSH target: paramiko-based in-process server
- SSH agent: in-process fake agent implementing the SSH agent protocol
  using paramiko's cryptographic primitives for signing
- ssh-mitm: started as a subprocess
- SSH client: OpenSSH subprocess (ssh)
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Generator

import paramiko
import pytest

# Apply the channel monkey-patch in the test process so that the in-process
# mock SSH targets also receive signal requests via check_channel_signal_request.
from sshmitm.workarounds.monkeypatch import patch_channel
patch_channel()

from sshmitm.mockserver import (
    MockAgent,
    NoneAuthServer,
    PublicKeyServer,
    RecordingServer,
    start_server_thread,
)


def _ssh_mitm_bin() -> str:
    """Return the path to the ssh-mitm binary, searching the active venv first."""
    found = shutil.which("ssh-mitm")
    if found:
        return found
    # Fall back to the same bin/ directory as the running Python interpreter
    candidate = Path(sys.executable).parent / "ssh-mitm"
    if candidate.exists():
        return str(candidate)
    raise FileNotFoundError("ssh-mitm not found — install it into the active venv")


# ---------------------------------------------------------------------------
# Port utilities
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    raise TimeoutError(f"Port {port} did not open within {timeout}s")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def _session_keys() -> tuple[paramiko.PKey, paramiko.PKey]:
    """(target_host_key, client_key) — generated once per test session."""
    host_key = paramiko.RSAKey.generate(2048)
    client_key = paramiko.RSAKey.generate(2048)
    return host_key, client_key


@pytest.fixture(scope="session")
def mock_ssh_target(
    _session_keys: tuple[paramiko.PKey, paramiko.PKey],
) -> Generator[int, None, None]:
    """Start mock SSH target. Yields the listening port."""
    host_key, client_key = _session_keys
    port, stop, _ = start_server_thread(lambda: PublicKeyServer(client_key), host_key=host_key)
    yield port
    stop.set()


@pytest.fixture
def fake_agent(
    tmp_path: Path,
    _session_keys: tuple[paramiko.PKey, paramiko.PKey],
) -> Generator[MockAgent, None, None]:
    """Start fake SSH agent, set SSH_AUTH_SOCK to its socket path."""
    _, client_key = _session_keys
    agent = MockAgent(client_key)
    sock_path = str(tmp_path / "agent.sock")
    agent.start(sock_path)
    old_sock = os.environ.get("SSH_AUTH_SOCK")
    os.environ["SSH_AUTH_SOCK"] = sock_path
    yield agent
    agent.stop()
    if old_sock is None:
        os.environ.pop("SSH_AUTH_SOCK", None)
    else:
        os.environ["SSH_AUTH_SOCK"] = old_sock


@pytest.fixture
def client_key_file(
    tmp_path: Path,
    _session_keys: tuple[paramiko.PKey, paramiko.PKey],
) -> Path:
    """Write the client private key to a temp file (chmod 600) for ssh -i."""
    _, client_key = _session_keys
    key_file = tmp_path / "client_rsa"
    client_key.write_private_key_file(str(key_file))
    os.chmod(str(key_file), 0o600)
    return key_file


@pytest.fixture
def mitm_trivial_auth(
    tmp_path: Path,
    mock_ssh_target: int,
    fake_agent: MockAgent,
) -> Generator[tuple[int, Path], None, None]:
    """Start ssh-mitm with --enable-trivial-auth pointing at the mock target.

    fake_agent is a dependency so SSH_AUTH_SOCK is set before ssh-mitm starts
    (ssh-mitm inherits it, though it does not use it directly).

    Yields (mitm_port, session_log_dir).
    """
    mitm_port = _free_port()
    log_dir = tmp_path / "sessions"
    log_dir.mkdir()

    proc = subprocess.Popen(
        [
            _ssh_mitm_bin(), "server",
            "--enable-trivial-auth",
            "--session-log-dir", str(log_dir),
            "--listen-port", str(mitm_port),
            "--remote-host", "127.0.0.1",
            "--remote-port", str(mock_ssh_target),
            "--disable-remote-fingerprint-warning",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_port(mitm_port)
        yield mitm_port, log_dir
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture(scope="session")
def mock_none_auth_target(
    _session_keys: tuple[paramiko.PKey, paramiko.PKey],
) -> Generator[int, None, None]:
    """Start a mock SSH target that only accepts none auth. Yields the port."""
    host_key, _ = _session_keys
    port, stop, _ = start_server_thread(lambda: NoneAuthServer(), host_key=host_key)
    yield port
    stop.set()


@pytest.fixture
def mitm_none_auth(
    tmp_path: Path,
    mock_none_auth_target: int,
) -> Generator[int, None, None]:
    """Start ssh-mitm pointing at the none-auth mock target.

    No special flags are needed: none auth passthrough auto-detects that the
    remote accepts none auth during the banner-probe phase.

    Yields the MITM listening port.
    """
    mitm_port = _free_port()

    proc = subprocess.Popen(
        [
            _ssh_mitm_bin(), "server",
            "--listen-port", str(mitm_port),
            "--remote-host", "127.0.0.1",
            "--remote-port", str(mock_none_auth_target),
            "--disable-remote-fingerprint-warning",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_port(mitm_port)
        yield mitm_port
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture
def recording_target(
    _session_keys: tuple[paramiko.PKey, paramiko.PKey],
) -> Generator[tuple[int, RecordingServer], None, None]:
    """Start a recording mock SSH target. Yields (port, iface)."""
    host_key, _ = _session_keys
    iface = RecordingServer()
    port, stop, _ = start_server_thread(lambda: iface, host_key=host_key, connection_timeout=30.0)
    yield port, iface
    stop.set()


@pytest.fixture
def mitm_recording(
    tmp_path: Path,
    recording_target: tuple[int, RecordingServer],
) -> Generator[tuple[int, RecordingServer], None, None]:
    """Start ssh-mitm pointing at the recording mock target.

    Yields (mitm_port, iface) so tests can inspect what the target received.
    """
    target_port, iface = recording_target
    mitm_port = _free_port()

    proc = subprocess.Popen(
        [
            _ssh_mitm_bin(), "server",
            "--listen-port", str(mitm_port),
            "--remote-host", "127.0.0.1",
            "--remote-port", str(target_port),
            "--disable-remote-fingerprint-warning",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_port(mitm_port)
        yield mitm_port, iface
    finally:
        proc.terminate()
        proc.wait(timeout=5)
