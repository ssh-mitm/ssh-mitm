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

import subprocess
from typing import TYPE_CHECKING, Callable, Generator

import paramiko
import paramiko.common
import pytest

from tests.integration.conftest import _free_port, _ssh_mitm_bin, _wait_port
from sshmitm.mockserver import KeyboardInteractiveServer, start_server_thread

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Credential constants
# ---------------------------------------------------------------------------

_SINGLE_PASSWORD = "correct-password"

_MULTI_TOKEN = "123456"
_MULTI_PASSWORD = "secret"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mitm_single_prompt(tmp_path: "Path") -> "Generator[int, None, None]":
    """MITM forwarding to a single-prompt keyboard-interactive target."""
    target_port, stop = start_server_thread(
        lambda: KeyboardInteractiveServer(
            prompts=[("Password: ", False)],
            answers=[_SINGLE_PASSWORD],
        )
    )
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
    target_port, stop = start_server_thread(
        lambda: KeyboardInteractiveServer(
            prompts=[("OTP Token: ", True), ("Password: ", False)],
            answers=[_MULTI_TOKEN, _MULTI_PASSWORD],
            name="Two-Factor Authentication",
            instructions="Enter your OTP token and password.",
        )
    )
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
# Helper
# ---------------------------------------------------------------------------

def _kbdinteractive_connect(
    mitm_port: int,
    handler: Callable[[str, str, list[tuple[str, bool]]], list[str]],
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
# Tests: single-prompt passthrough
# ---------------------------------------------------------------------------

def test_single_prompt_auth_success(mitm_single_prompt: int) -> None:
    """Correct password through single-prompt MITM → AUTH_SUCCESSFUL."""
    received: list[tuple] = []

    def handler(title: str, instructions: str, prompt_list: list[tuple[str, bool]]) -> list[str]:
        received.append((title, instructions, prompt_list))
        return [_SINGLE_PASSWORD]

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
        return [_SINGLE_PASSWORD]

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
        return [_MULTI_TOKEN, _MULTI_PASSWORD]

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
        return [_MULTI_TOKEN, _MULTI_PASSWORD]

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
