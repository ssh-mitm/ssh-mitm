"""Regression tests for exec-command handling in sshmitm.mockserver.

check_channel_exec_request() implementations here spawn a worker thread and
return True; paramiko sends the pending CHANNEL_SUCCESS reply for that
request on the *caller's* thread right after the return. If the worker
thread writes data and closes the channel before that reply goes out, the
client sees the channel close (or further traffic) ahead of the reply and
raises "Channel closed." instead of completing exec_command().

This raced reliably (100% reproducible locally) before _CHANNEL_REQUEST_REPLY_GRACE
was added in every affected _exec/_run_exec/_mock_exec implementation - across
NoneAuthServer, PublicKeyServer, PasswordServer, MockServerInterface/
MultiUserMockServer (the `ssh-mitm mock-server` CLI backend), and the tutorial
system's _TutorialServer (sshmitm/tutorial/_runner.py). Each variant is
exercised here directly via paramiko, with no ssh-mitm proxying involved, to
isolate the mock servers' own exec handling from the rest of the stack.

The shell request path (check_channel_shell_request) does not need the same
guard: its worker thread only calls sendall() and then blocks on recv(),
never closing the channel up front, so there's nothing for the pending
CHANNEL_SUCCESS reply to race against.
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Generator

import paramiko
import pytest

from sshmitm.mockserver import (
    MockServerInterface,
    MultiUserMockServer,
    NoneAuthServer,
    PasswordServer,
    PublicKeyServer,
    start_server_thread,
)
from sshmitm.tutorial._runner import _TutorialServer

# check_channel_exec_request's worker-thread race is timing-dependent; a
# single passing iteration doesn't prove it's fixed. This matched the
# regression's ~100% reproduction rate locally before the fix.
_ITERATIONS = 10


def _exec_many(connect: Callable[[], paramiko.SSHClient], command: str) -> None:
    for i in range(_ITERATIONS):
        client = connect()
        try:
            _, stdout, _ = client.exec_command(command)
            stdout.channel.recv_exit_status()
        except paramiko.SSHException as exc:
            pytest.fail(f"iteration {i}: exec_command raised {exc!r}")
        finally:
            client.close()


@pytest.fixture
def rsa_key() -> paramiko.RSAKey:
    return paramiko.RSAKey.generate(1024)


def _connect(port: int, **kwargs: object) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1", port=port, timeout=5, look_for_keys=False, allow_agent=False, **kwargs
    )
    return client


class TestNoneAuthServerExec:
    @pytest.fixture
    def target_port(self) -> Generator[int, None, None]:
        host_key = paramiko.RSAKey.generate(2048)
        port, stop, _ = start_server_thread(NoneAuthServer, host_key=host_key)
        yield port
        stop.set()

    def test_exec_does_not_race_channel_success(self, target_port: int) -> None:
        # SSHClient.connect() has no "none" auth strategy - drive the
        # Transport directly instead.
        for i in range(_ITERATIONS):
            sock = socket.create_connection(("127.0.0.1", target_port), timeout=5)
            transport = paramiko.Transport(sock)
            try:
                transport.start_client(timeout=5)
                transport.auth_none("testuser")
                channel = transport.open_session(timeout=5)
                try:
                    channel.exec_command("echo hi")
                    channel.recv_exit_status()
                except paramiko.SSHException as exc:
                    pytest.fail(f"iteration {i}: exec_command raised {exc!r}")
            finally:
                transport.close()


class TestPublicKeyServerExec:
    @pytest.fixture
    def target_port(self, rsa_key: paramiko.RSAKey) -> Generator[int, None, None]:
        host_key = paramiko.RSAKey.generate(2048)
        port, stop, _ = start_server_thread(
            lambda: PublicKeyServer(rsa_key), host_key=host_key
        )
        yield port
        stop.set()

    def test_exec_does_not_race_channel_success(
        self, target_port: int, rsa_key: paramiko.RSAKey
    ) -> None:
        _exec_many(
            lambda: _connect(target_port, username="testuser", pkey=rsa_key),
            "echo hi",
        )


class TestPasswordServerExec:
    @pytest.fixture
    def target_port(self) -> Generator[int, None, None]:
        host_key = paramiko.RSAKey.generate(2048)
        port, stop, _ = start_server_thread(
            lambda: PasswordServer("s3cret"), host_key=host_key
        )
        yield port
        stop.set()

    def test_exec_does_not_race_channel_success(self, target_port: int) -> None:
        _exec_many(
            lambda: _connect(target_port, username="testuser", password="s3cret"),
            "echo hi",
        )


class TestMockServerInterfaceExec:
    """Backs the `ssh-mitm mock-server` CLI command."""

    @pytest.fixture
    def target_port(self, rsa_key: paramiko.RSAKey) -> Generator[int, None, None]:
        host_key = paramiko.RSAKey.generate(2048)
        port, stop, _ = start_server_thread(
            lambda: MockServerInterface("testuser", "s3cret", [rsa_key], False),
            host_key=host_key,
        )
        yield port
        stop.set()

    def test_exec_does_not_race_channel_success(self, target_port: int) -> None:
        _exec_many(
            lambda: _connect(target_port, username="testuser", password="s3cret"),
            "echo hi",
        )


class TestMultiUserMockServerExec:
    @pytest.fixture
    def target_port(self, rsa_key: paramiko.RSAKey) -> Generator[int, None, None]:
        host_key = paramiko.RSAKey.generate(2048)
        users = {"key": MultiUserMockServer.pubkey_user([rsa_key])}
        port, stop, _ = start_server_thread(
            lambda: MultiUserMockServer(users), host_key=host_key
        )
        yield port
        stop.set()

    def test_exec_does_not_race_channel_success(
        self, target_port: int, rsa_key: paramiko.RSAKey
    ) -> None:
        _exec_many(
            lambda: _connect(target_port, username="key", pkey=rsa_key),
            "echo hi",
        )


class TestTutorialServerExec:
    """Backs the `ssh-mitm tutorial` mock SSH targets."""

    @pytest.fixture
    def target_port(self, rsa_key: paramiko.RSAKey) -> Generator[int, None, None]:
        host_key = paramiko.RSAKey.generate(2048)
        users = {"key": MultiUserMockServer.pubkey_user([rsa_key])}
        server = _TutorialServer(
            users,
            on_auth=lambda *_args: None,
            exec_outputs={"echo hi": b"hi\n"},
        )
        port, stop, _ = start_server_thread(lambda: server, host_key=host_key)
        yield port
        stop.set()

    def test_exec_does_not_race_channel_success(
        self, target_port: int, rsa_key: paramiko.RSAKey
    ) -> None:
        _exec_many(
            lambda: _connect(target_port, username="key", pkey=rsa_key),
            "echo hi",
        )
