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
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Generator

import paramiko
import pytest
from paramiko.message import Message


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
# Mock SSH target server (paramiko)
# ---------------------------------------------------------------------------

class _TargetServerInterface(paramiko.ServerInterface):
    """Accepts one specific public key, executes commands and returns output."""

    def __init__(self, accepted_key: paramiko.PKey) -> None:
        self._accepted_key = accepted_key

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        return (
            paramiko.common.AUTH_SUCCESSFUL
            if key.get_base64() == self._accepted_key.get_base64()
            else paramiko.common.AUTH_FAILED
        )

    def get_allowed_auths(self, username: str) -> str:
        return "publickey"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes
    ) -> bool:
        threading.Thread(
            target=self._exec, args=(channel, command), daemon=True
        ).start()
        return True

    @staticmethod
    def _exec(channel: paramiko.Channel, command: bytes) -> None:
        try:
            channel.sendall(f"REMOTE_OK:{command.decode()}\n".encode())
            channel.send_exit_status(0)
        finally:
            channel.close()


def _start_mock_ssh_target(
    host_key: paramiko.PKey, client_key: paramiko.PKey
) -> tuple[int, threading.Event]:
    stop = threading.Event()
    ready = threading.Event()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    sock.listen(5)
    sock.settimeout(0.5)

    def _handle(conn: socket.socket) -> None:
        t = paramiko.Transport(conn)
        t.add_server_key(host_key)
        t.start_server(server=_TargetServerInterface(client_key))
        t.join(timeout=10)

    def _serve() -> None:
        ready.set()
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                threading.Thread(target=_handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
        sock.close()

    threading.Thread(target=_serve, daemon=True).start()
    ready.wait(timeout=2.0)
    return port, stop


# ---------------------------------------------------------------------------
# Fake SSH agent (paramiko-based signing)
#
# Implements the SSH agent protocol over a Unix socket.
# Uses paramiko.PKey.sign_ssh_data() for all signing operations so that
# the cryptographic behaviour is identical to a real agent loaded with the
# same key.
# ---------------------------------------------------------------------------

class FakeAgent:
    """Minimal SSH agent protocol server backed by a paramiko key."""

    _AGENTC_REQUEST_IDENTITIES = 11
    _AGENT_IDENTITIES_ANSWER = 12
    _AGENTC_SIGN_REQUEST = 13
    _AGENT_SIGN_RESPONSE = 14
    _AGENT_FAILURE = 5

    def __init__(self, key: paramiko.PKey) -> None:
        self._key = key
        self._stop = threading.Event()
        self._sock: socket.socket | None = None

    def start(self, path: str) -> None:
        self._sock = socket.socket(socket.AF_UNIX)
        self._sock.bind(path)
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
                threading.Thread(
                    target=self._handle, args=(conn,), daemon=True
                ).start()
            except (OSError, socket.timeout):
                continue

    @staticmethod
    def _recv(conn: socket.socket) -> bytes | None:
        hdr = b""
        while len(hdr) < 4:
            chunk = conn.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        length = struct.unpack(">I", hdr)[0]
        buf = b""
        while len(buf) < length:
            chunk = conn.recv(length - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _send(conn: socket.socket, data: bytes) -> None:
        conn.sendall(struct.pack(">I", len(data)) + data)

    def _handle(self, conn: socket.socket) -> None:
        try:
            while True:
                msg = self._recv(conn)
                if msg is None:
                    break
                msg_type = msg[0]

                if msg_type == self._AGENTC_REQUEST_IDENTITIES:
                    key_blob = self._key.asbytes()
                    comment = b"integration-test-key"
                    body = (
                        bytes([self._AGENT_IDENTITIES_ANSWER])
                        + struct.pack(">I", 1)
                        + struct.pack(">I", len(key_blob)) + key_blob
                        + struct.pack(">I", len(comment)) + comment
                    )
                    self._send(conn, body)

                elif msg_type == self._AGENTC_SIGN_REQUEST:
                    # string key_blob, string data_to_sign, uint32 flags
                    off = 1
                    kb_len = struct.unpack(">I", msg[off:off + 4])[0]
                    off += 4 + kb_len  # key identity — we only serve one key
                    data_len = struct.unpack(">I", msg[off:off + 4])[0]
                    off += 4
                    data_to_sign = msg[off:off + data_len]

                    sig: Message = self._key.sign_ssh_data(data_to_sign)
                    sig_blob = sig.asbytes()
                    body = (
                        bytes([self._AGENT_SIGN_RESPONSE])
                        + struct.pack(">I", len(sig_blob)) + sig_blob
                    )
                    self._send(conn, body)

                else:
                    self._send(conn, bytes([self._AGENT_FAILURE]))
        except Exception:
            pass
        finally:
            conn.close()


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
    port, stop = _start_mock_ssh_target(host_key, client_key)
    yield port
    stop.set()


@pytest.fixture
def fake_agent(
    tmp_path: Path,
    _session_keys: tuple[paramiko.PKey, paramiko.PKey],
) -> Generator[FakeAgent, None, None]:
    """Start fake SSH agent, set SSH_AUTH_SOCK to its socket path."""
    _, client_key = _session_keys
    agent = FakeAgent(client_key)
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
    fake_agent: FakeAgent,
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
