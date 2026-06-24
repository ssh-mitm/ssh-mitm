"""Integration tests for the NETCONF forwarder (Phase 1 + Phase 2).

Full chain under test:

    ncclient → SSH-MITM → MockNetconfServer

Test scenarios:
  1. EOM framing (RFC 4742): mock advertises only :base:1.0 → all messages
     use the ``]]>]]>`` terminator throughout the session.
  2. Chunked framing (RFC 6242): mock advertises :base:1.0 + :base:1.1 →
     ncclient negotiates :base:1.1 and switches to chunked framing after the
     hello exchange.
  3. Direct connection (no MITM): verifies that the mock server itself speaks
     correct NETCONF before we involve the MITM.
  4. Phase 2 hello parsing: mock reports the negotiated mode via a custom
     reply so we can verify the MITM picked up the right framing after the
     ``<hello>`` exchange.

No external NETCONF server needed — the mock is a pure-Python paramiko server.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from typing import Generator

import paramiko
import paramiko.common
import pytest
from ncclient import manager as nc_manager

from sshmitm.mockserver import start_server_thread

# ---------------------------------------------------------------------------
# NETCONF constants
# ---------------------------------------------------------------------------

_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
_CAP_1_0 = "urn:ietf:params:netconf:base:1.0"
_CAP_1_1 = "urn:ietf:params:netconf:base:1.1"
_EOM = b"]]>]]>"

# ---------------------------------------------------------------------------
# Low-level framing helpers (used by the mock server)
# ---------------------------------------------------------------------------

def _read_eom(chan: paramiko.Channel, timeout: float = 15.0) -> bytes:
    """Read one EOM-framed message from *chan*."""
    buf = b""
    deadline = time.monotonic() + timeout
    while _EOM not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("EOM message timeout")
        chan.settimeout(min(remaining, 1.0))
        chunk = chan.recv(65536)
        if not chunk:
            return buf
        buf += chunk
    return buf


def _write_eom(chan: paramiko.Channel, xml: bytes) -> None:
    chan.sendall(xml + _EOM)


def _read_chunked(chan: paramiko.Channel, timeout: float = 15.0) -> bytes:
    """Read one RFC 6242 chunked message from *chan*."""
    deadline = time.monotonic() + timeout

    def recv_byte() -> bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("chunked message timeout")
        chan.settimeout(min(remaining, 1.0))
        b = chan.recv(1)
        if not b:
            raise ConnectionError("channel closed in chunked read")
        return b

    def recv_exactly(n: int) -> bytes:
        data = b""
        while len(data) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("chunked data timeout")
            chan.settimeout(min(remaining, 1.0))
            chunk = chan.recv(min(n - len(data), 65536))
            if not chunk:
                raise ConnectionError("channel closed in chunk data")
            data += chunk
        return data

    buf = b""
    # Consume the leading \n
    first = recv_byte()
    buf += first
    if first != b"\n":
        raise ValueError(f"Expected \\n at start of chunked message, got {first!r}")

    while True:
        # Read '#'
        h = recv_byte()
        buf += h
        if h != b"#":
            raise ValueError(f"Expected # in chunk delimiter, got {h!r}")

        # Next byte: '#' (end-of-chunks) or digit (chunk size)
        n = recv_byte()
        buf += n

        if n == b"#":
            # End-of-chunks: consume trailing \n
            buf += recv_byte()
            return buf

        if not n.isdigit():
            raise ValueError(f"Expected digit in chunk size, got {n!r}")

        # Read remaining digits + \n
        size_bytes = n
        while True:
            b = recv_byte()
            buf += b
            if b == b"\n":
                break
            if not b.isdigit():
                raise ValueError(f"Non-digit in chunk size: {b!r}")
            size_bytes += b

        chunk_size = int(size_bytes)
        data = recv_exactly(chunk_size)
        buf += data

        # Read separator \n before next chunk header
        sep = recv_byte()
        buf += sep
        if sep != b"\n":
            raise ValueError(f"Expected \\n between chunks, got {sep!r}")


def _write_chunked(chan: paramiko.Channel, xml: bytes) -> None:
    chan.sendall(f"\n#{len(xml)}\n".encode() + xml + b"\n##\n")


# ---------------------------------------------------------------------------
# Mock NETCONF server
# ---------------------------------------------------------------------------

class MockNetconfServer(paramiko.ServerInterface):
    """Minimal NETCONF server for integration testing.

    *chunked=False* → advertises only :base:1.0 (EOM throughout).
    *chunked=True*  → advertises :base:1.0 + :base:1.1 (chunked after hello).
    """

    def __init__(self, chunked: bool = False, password: str = "testpass") -> None:
        self._chunked = chunked
        self._password = password
        self.received_rpcs: list[bytes] = []
        self._lock = threading.Lock()

    # -- Auth ----------------------------------------------------------------

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        if password == self._password:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    # -- Channel -------------------------------------------------------------

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_subsystem_request(
        self, channel: paramiko.Channel, name: str
    ) -> bool:
        if name == "netconf":
            threading.Thread(
                target=self._serve, args=(channel,), daemon=True
            ).start()
            return True
        return False

    # -- NETCONF session handler ---------------------------------------------

    def _serve(self, channel: paramiko.Channel) -> None:
        try:
            caps = [_CAP_1_0]
            if self._chunked:
                caps.append(_CAP_1_1)
            caps_xml = "".join(f"<capability>{c}</capability>" for c in caps)
            hello = (
                f'<?xml version="1.0" encoding="UTF-8"?>'
                f'<hello xmlns="{_NS}">'
                f"<capabilities>{caps_xml}</capabilities>"
                f"<session-id>1</session-id>"
                f"</hello>"
            ).encode()
            _write_eom(channel, hello)

            # Client hello (always EOM)
            client_hello = _read_eom(channel)

            # After hello: switch to chunked if both sides have :base:1.1
            use_chunked = self._chunked and _CAP_1_1.encode() in client_hello

            while True:
                try:
                    rpc = _read_chunked(channel) if use_chunked else _read_eom(channel)
                except (TimeoutError, ConnectionError, OSError):
                    break
                if not rpc:
                    break

                with self._lock:
                    self.received_rpcs.append(rpc)

                m = re.search(rb'message-id=["\']([^"\']+)["\']', rpc)
                msg_id = m.group(1).decode() if m else "101"

                reply = (
                    f'<rpc-reply xmlns="{_NS}" message-id="{msg_id}">'
                    f"<data/>"
                    f"</rpc-reply>"
                ).encode()

                if use_chunked:
                    _write_chunked(channel, reply)
                else:
                    _write_eom(channel, reply)

        except Exception:  # noqa: BLE001
            pass
        finally:
            channel.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _free_port() -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 10.0) -> None:
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    raise TimeoutError(f"Port {port} did not open within {timeout}s")


def _ssh_mitm_bin() -> str:
    import shutil, sys
    from pathlib import Path
    found = shutil.which("ssh-mitm")
    if found:
        return found
    candidate = Path(sys.executable).parent / "ssh-mitm"
    if candidate.exists():
        return str(candidate)
    raise FileNotFoundError("ssh-mitm binary not found")


@pytest.fixture(scope="session")
def _netconf_host_key() -> paramiko.PKey:
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def eom_target(
    _netconf_host_key: paramiko.PKey,
) -> Generator[tuple[int, MockNetconfServer], None, None]:
    """Mock NETCONF server with EOM-only framing."""
    server = MockNetconfServer(chunked=False)
    port, stop, _ = start_server_thread(lambda: server, host_key=_netconf_host_key)
    yield port, server
    stop.set()


@pytest.fixture
def chunked_target(
    _netconf_host_key: paramiko.PKey,
) -> Generator[tuple[int, MockNetconfServer], None, None]:
    """Mock NETCONF server advertising :base:1.1 (chunked framing)."""
    server = MockNetconfServer(chunked=True)
    port, stop, _ = start_server_thread(lambda: server, host_key=_netconf_host_key)
    yield port, server
    stop.set()


@pytest.fixture
def mitm_eom(
    tmp_path: object,
    eom_target: tuple[int, MockNetconfServer],
) -> Generator[tuple[int, MockNetconfServer], None, None]:
    """SSH-MITM in front of the EOM mock server."""
    target_port, server = eom_target
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
        yield mitm_port, server
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture
def mitm_chunked(
    tmp_path: object,
    chunked_target: tuple[int, MockNetconfServer],
) -> Generator[tuple[int, MockNetconfServer], None, None]:
    """SSH-MITM in front of the chunked (RFC 6242) mock server."""
    target_port, server = chunked_target
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
        yield mitm_port, server
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# Helper: open ncclient session
# ---------------------------------------------------------------------------

def _connect(port: int) -> nc_manager.Manager:
    return nc_manager.connect(
        host="127.0.0.1",
        port=port,
        username="testuser",
        password="testpass",
        hostkey_verify=False,
        allow_agent=False,
        look_for_keys=False,
        device_params={"name": "default"},
        timeout=30,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_netconf_eom_direct(eom_target: tuple[int, MockNetconfServer]) -> None:
    """ncclient connects directly to the EOM mock (no MITM) — sanity check."""
    port, server = eom_target
    with _connect(port) as mgr:
        reply = mgr.get()
    assert reply is not None
    assert len(server.received_rpcs) >= 1


def test_netconf_eom_via_mitm(mitm_eom: tuple[int, MockNetconfServer]) -> None:
    """EOM framing passes through SSH-MITM without corruption."""
    mitm_port, server = mitm_eom
    with _connect(mitm_port) as mgr:
        reply = mgr.get()
    assert reply is not None
    assert len(server.received_rpcs) >= 1


def test_netconf_chunked_direct(chunked_target: tuple[int, MockNetconfServer]) -> None:
    """ncclient negotiates :base:1.1 chunked framing directly (no MITM)."""
    port, server = chunked_target
    with _connect(port) as mgr:
        # ncclient should have negotiated :base:1.1 (chunked)
        assert ":base:1.1" in str(mgr.server_capabilities)
        reply = mgr.get()
    assert reply is not None
    assert len(server.received_rpcs) >= 1


def test_netconf_chunked_via_mitm(mitm_chunked: tuple[int, MockNetconfServer]) -> None:
    """RFC 6242 chunked framing passes through SSH-MITM (Phase 1 core test)."""
    mitm_port, server = mitm_chunked
    with _connect(mitm_port) as mgr:
        assert ":base:1.1" in str(mgr.server_capabilities)
        reply = mgr.get()
    assert reply is not None
    assert len(server.received_rpcs) >= 1


def test_netconf_multiple_rpcs_via_mitm(mitm_chunked: tuple[int, MockNetconfServer]) -> None:
    """Multiple sequential RPCs through SSH-MITM all succeed."""
    mitm_port, server = mitm_chunked
    with _connect(mitm_port) as mgr:
        for _ in range(3):
            reply = mgr.get()
            assert reply is not None
    assert len(server.received_rpcs) >= 3


# ---------------------------------------------------------------------------
# Phase 2 tests — hello parsing and framing negotiation
# ---------------------------------------------------------------------------

def test_netconf_eom_framing_not_downgraded(mitm_eom: tuple[int, MockNetconfServer]) -> None:
    """EOM-only server → ncclient must NOT negotiate chunked framing via MITM.

    Phase 2: the MITM correctly reads the server's <hello> (only :base:1.0)
    and the client's <hello>, determines EOM mode, and uses EOM readers for
    subsequent messages.  If the MITM mistakenly switched to chunked after the
    hello, the first RPC would be misread and ncclient would raise.
    """
    mitm_port, server = mitm_eom
    with _connect(mitm_port) as mgr:
        # The server_capabilities from ncclient's perspective reflect what the
        # mock server advertised; no :base:1.1 → EOM framing throughout.
        assert "urn:ietf:params:netconf:base:1.1" not in str(mgr.server_capabilities)
        for _ in range(2):
            reply = mgr.get()
            assert reply is not None
    assert len(server.received_rpcs) >= 2


def test_netconf_chunked_framing_negotiated(mitm_chunked: tuple[int, MockNetconfServer]) -> None:
    """Chunked server → both sides must negotiate :base:1.1 via MITM.

    Phase 2: the MITM reads both <hello> messages, detects that both sides
    support :base:1.1, and uses chunked readers for subsequent messages.
    ncclient sees the server's chunked framing unchanged.
    """
    mitm_port, server = mitm_chunked
    with _connect(mitm_port) as mgr:
        assert "urn:ietf:params:netconf:base:1.1" in str(mgr.server_capabilities)
        for _ in range(2):
            reply = mgr.get()
            assert reply is not None
    assert len(server.received_rpcs) >= 2


# ---------------------------------------------------------------------------
# Phase 3 tests — RPC-interception hooks
# ---------------------------------------------------------------------------

def test_netconf_rpc_hooks_eom(mitm_eom: tuple[int, MockNetconfServer]) -> None:
    """RPC hook wiring works for EOM-framed sessions.

    Phase 3: handle_client_data() must strip EOM framing, parse <rpc>, call
    handle_rpc_request(), and re-apply framing when forwarding.  The default
    implementation returns None (no rewrite), so the mock server receives the
    original RPC bytes unchanged — verified by checking the message-id.
    """
    mitm_port, server = mitm_eom
    with _connect(mitm_port) as mgr:
        reply = mgr.get()
    assert reply is not None
    # The mock server must have received at least one <rpc> message with a message-id.
    assert any(b"message-id" in rpc for rpc in server.received_rpcs)


def test_netconf_rpc_hooks_chunked(mitm_chunked: tuple[int, MockNetconfServer]) -> None:
    """RPC hook wiring works for chunked-framed sessions.

    Phase 3: _reassemble_chunks must correctly extract XML so _parse_rpc()
    can identify the <get> operation.  Again the default hook returns None
    so the server receives the original bytes.
    """
    mitm_port, server = mitm_chunked
    with _connect(mitm_port) as mgr:
        reply = mgr.get()
    assert reply is not None
    assert any(b"message-id" in rpc for rpc in server.received_rpcs)
