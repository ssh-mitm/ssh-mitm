"""Integration tests for RFC 4256 keyboard-interactive passthrough.

Stack:
  paramiko client (keyboard-interactive)
    ↓  SSH-MITM proxies prompts/responses transparently
  ssh-mitm (subprocess)
    ↓  auth_keyboard_interactive → remote server
  Mock SSH target (paramiko, in-process, keyboard-interactive only)

Tests cover:
- Single-prompt pass-through (correct and wrong credentials)
- Multi-prompt / multi-factor pass-through (correct and wrong credentials)
- Prompts forwarded with correct name, instructions, echo flags
"""

from __future__ import annotations

import socket
import subprocess
import threading
import time
from typing import Generator

import paramiko
import paramiko.common
import pytest

from tests.integration.conftest import _free_port, _ssh_mitm_bin, _wait_port


# ---------------------------------------------------------------------------
# Mock SSH target servers for keyboard-interactive
# ---------------------------------------------------------------------------

class _SinglePromptServer(paramiko.ServerInterface):
    """Accepts keyboard-interactive with a single 'Password:' prompt."""

    VALID_PASSWORD = "correct-password"  # noqa: S105

    def get_allowed_auths(self, username: str) -> str:
        return "keyboard-interactive"

    def check_auth_none(self, username: str) -> int:
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: str
    ) -> paramiko.server.InteractiveQuery:
        query = paramiko.server.InteractiveQuery("", "")
        query.add_prompt("Password: ", False)
        return query

    def check_auth_interactive_response(self, responses: list[str]) -> int:
        if responses and responses[0] == self.VALID_PASSWORD:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True


class _MultiPromptServer(paramiko.ServerInterface):
    """Accepts keyboard-interactive with two prompts: OTP token + password."""

    VALID_TOKEN = "123456"
    VALID_PASSWORD = "secret"  # noqa: S105

    def get_allowed_auths(self, username: str) -> str:
        return "keyboard-interactive"

    def check_auth_none(self, username: str) -> int:
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: str
    ) -> paramiko.server.InteractiveQuery:
        query = paramiko.server.InteractiveQuery(
            name="Two-Factor Authentication",
            instructions="Enter your OTP token and password.",
        )
        query.add_prompt("OTP Token: ", True)   # echo=True
        query.add_prompt("Password: ", False)    # echo=False (hidden)
        return query

    def check_auth_interactive_response(self, responses: list[str]) -> int:
        if (
            len(responses) == 2
            and responses[0] == self.VALID_TOKEN
            and responses[1] == self.VALID_PASSWORD
        ):
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True


def _start_mock_kbdinteractive_target(
    server_interface_class: type[paramiko.ServerInterface],
) -> tuple[int, threading.Event]:
    """Start a paramiko SSH server using the given ServerInterface. Returns (port, stop_event)."""
    host_key = paramiko.RSAKey.generate(2048)
    stop = threading.Event()
    ready = threading.Event()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    sock.listen(5)
    sock.settimeout(0.5)

    def _handle(conn: socket.socket) -> None:
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        try:
            transport.start_server(server=server_interface_class())
            transport.join(timeout=15)
        except Exception:  # noqa: BLE001
            pass  # Connection resets from MITM banner-probing are expected

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


def _kbdinteractive_connect(
    mitm_port: int,
    handler: "Callable[[str, str, list[tuple[str, bool]]], list[str]]",
    submethods: str = "",
) -> bool:
    """Connect to MITM via keyboard-interactive. Returns True on auth success."""
    transport = paramiko.Transport(("127.0.0.1", mitm_port))
    transport.start_client(timeout=10)
    try:
        remaining = transport.auth_interactive("testuser", handler, submethods)
        return remaining == []
    except paramiko.AuthenticationException:
        return False
    finally:
        transport.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mitm_single_prompt(tmp_path: "Path") -> "Generator[int, None, None]":
    """MITM forwarding to a single-prompt keyboard-interactive target."""
    target_port, stop = _start_mock_kbdinteractive_target(_SinglePromptServer)
    mitm_port = _free_port()

    proc = subprocess.Popen(
        [
            _ssh_mitm_bin(), "server",
            "--disable-password-auth",
            "--disable-publickey-auth",
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
        yield mitm_port
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        stop.set()


@pytest.fixture
def mitm_multi_prompt(tmp_path: "Path") -> "Generator[int, None, None]":
    """MITM forwarding to a two-prompt keyboard-interactive target."""
    target_port, stop = _start_mock_kbdinteractive_target(_MultiPromptServer)
    mitm_port = _free_port()

    proc = subprocess.Popen(
        [
            _ssh_mitm_bin(), "server",
            "--disable-password-auth",
            "--disable-publickey-auth",
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
        yield mitm_port
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        stop.set()


# ---------------------------------------------------------------------------
# Tests: single-prompt passthrough
# ---------------------------------------------------------------------------

def test_single_prompt_auth_success(mitm_single_prompt: int) -> None:
    """Correct password through single-prompt MITM → AUTH_SUCCESSFUL."""
    received: list[tuple] = []

    def handler(title: str, instructions: str, prompt_list: list[tuple[str, bool]]) -> list[str]:
        received.append((title, instructions, prompt_list))
        return [_SinglePromptServer.VALID_PASSWORD]

    assert _kbdinteractive_connect(mitm_single_prompt, handler) is True
    assert len(received) == 1, "Expected exactly one challenge round"


def test_single_prompt_auth_failure(mitm_single_prompt: int) -> None:
    """Wrong password through single-prompt MITM → AUTH_FAILED."""

    def handler(title: str, instructions: str, prompt_list: list[tuple[str, bool]]) -> list[str]:
        return ["wrong-password"]

    assert _kbdinteractive_connect(mitm_single_prompt, handler) is False


def test_single_prompt_forwarded_correctly(mitm_single_prompt: int) -> None:
    """MITM forwards prompt text and echo flag unchanged."""
    received: list[tuple] = []

    def handler(title: str, instructions: str, prompt_list: list[tuple[str, bool]]) -> list[str]:
        received.append((title, instructions, prompt_list))
        return [_SinglePromptServer.VALID_PASSWORD]

    _kbdinteractive_connect(mitm_single_prompt, handler)

    assert received, "No challenge received from MITM"
    _title, _instructions, prompts = received[0]
    assert len(prompts) == 1
    prompt_text, echo = prompts[0]
    assert "Password" in prompt_text
    assert echo is False


# ---------------------------------------------------------------------------
# Tests: multi-prompt passthrough
# ---------------------------------------------------------------------------

def test_multi_prompt_auth_success(mitm_multi_prompt: int) -> None:
    """Correct OTP+password through two-prompt MITM → AUTH_SUCCESSFUL."""
    received: list[tuple] = []

    def handler(title: str, instructions: str, prompt_list: list[tuple[str, bool]]) -> list[str]:
        received.append((title, instructions, prompt_list))
        return [_MultiPromptServer.VALID_TOKEN, _MultiPromptServer.VALID_PASSWORD]

    assert _kbdinteractive_connect(mitm_multi_prompt, handler) is True
    assert len(received) == 1


def test_multi_prompt_auth_failure(mitm_multi_prompt: int) -> None:
    """Wrong credentials through two-prompt MITM → AUTH_FAILED."""

    def handler(title: str, instructions: str, prompt_list: list[tuple[str, bool]]) -> list[str]:
        return ["wrong-token", "wrong-password"]

    assert _kbdinteractive_connect(mitm_multi_prompt, handler) is False


def test_multi_prompt_name_instructions_forwarded(mitm_multi_prompt: int) -> None:
    """MITM forwards name, instructions, prompt texts, and echo flags unchanged."""
    received: list[tuple] = []

    def handler(title: str, instructions: str, prompt_list: list[tuple[str, bool]]) -> list[str]:
        received.append((title, instructions, prompt_list))
        return [_MultiPromptServer.VALID_TOKEN, _MultiPromptServer.VALID_PASSWORD]

    _kbdinteractive_connect(mitm_multi_prompt, handler)

    assert received, "No challenge received from MITM"
    title, instructions, prompts = received[0]
    assert title == "Two-Factor Authentication"
    assert "OTP" in instructions or "token" in instructions.lower()
    assert len(prompts) == 2

    otp_prompt, otp_echo = prompts[0]
    pw_prompt, pw_echo = prompts[1]
    assert "OTP" in otp_prompt or "Token" in otp_prompt
    assert otp_echo is True
    assert "Password" in pw_prompt
    assert pw_echo is False
