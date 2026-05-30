"""paramiko ServerInterface implementations for SSH mock servers."""

from __future__ import annotations

import contextlib
import dataclasses
import shlex
import subprocess  # nosec B404
import threading
import time
from typing import TYPE_CHECKING

import paramiko
import paramiko.common
import paramiko.server

if TYPE_CHECKING:
    pass


@dataclasses.dataclass
class KbdintRound:
    """One round of a keyboard-interactive exchange.

    A single auth attempt may consist of multiple rounds sent one after the
    other.  Each round carries its own set of prompts and expected answers,
    plus optional *name* and *instructions* shown to the user.

    Example — OTP followed by a password in separate rounds::

        rounds = [
            KbdintRound(prompts=[("OTP Token: ", True)],  answers=["123456"]),
            KbdintRound(prompts=[("Password: ", False)],  answers=["secret"]),
        ]
    """

    prompts: list[tuple[str, bool]]
    answers: list[str]
    name: str = ""
    instructions: str = ""


@dataclasses.dataclass
class _UserConfig:
    allow_none: bool = False
    password: str | None = None
    pubkeys: list[paramiko.PKey] = dataclasses.field(default_factory=list)
    kbdint_prompts: list[tuple[str, bool]] = dataclasses.field(default_factory=list)
    kbdint_answers: list[str] = dataclasses.field(default_factory=list)
    kbdint_name: str = ""
    kbdint_instructions: str = ""
    kbdint_rounds: list[KbdintRound] = dataclasses.field(default_factory=list)


class NoneAuthServer(paramiko.ServerInterface):
    """Accepts none authentication for a single username."""

    def __init__(self, username: str = "testuser") -> None:
        self._username = username

    def get_allowed_auths(self, username: str) -> str:
        return "none" if username == self._username else "publickey"

    def check_auth_none(self, username: str) -> int:
        return (
            paramiko.common.AUTH_SUCCESSFUL
            if username == self._username
            else paramiko.common.AUTH_FAILED
        )

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


class PublicKeyServer(paramiko.ServerInterface):
    """Accepts one specific public key."""

    def __init__(self, accepted_key: paramiko.PKey) -> None:
        self._accepted_key = accepted_key

    def get_allowed_auths(self, username: str) -> str:
        return "publickey"

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        return (
            paramiko.common.AUTH_SUCCESSFUL
            if key.get_base64() == self._accepted_key.get_base64()
            else paramiko.common.AUTH_FAILED
        )

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


class PasswordServer(paramiko.ServerInterface):
    """Accepts password authentication."""

    def __init__(self, password: str, username: str = "testuser") -> None:
        self._password = password
        self._username = username

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        return (
            paramiko.common.AUTH_SUCCESSFUL
            if password == self._password
            else paramiko.common.AUTH_FAILED
        )

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


class RecordingServer(paramiko.ServerInterface):
    """Password-auth server that records PTY modes and received signals.

    After connecting a client, inspect ``pty_modes`` and ``signals`` to verify
    that the SSH-MITM proxy (or any other layer) forwarded them correctly.
    """

    def __init__(self, password: str = "testpass") -> None:
        self._password = password
        self.pty_modes: bytes | None = None
        self.signals: list[str] = []

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_auth_password(self, username: str, password: str) -> int:
        return (
            paramiko.common.AUTH_SUCCESSFUL
            if password == self._password
            else paramiko.common.AUTH_FAILED
        )

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

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
        self.pty_modes = modes
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        threading.Thread(target=self._shell, args=(channel,), daemon=True).start()
        return True

    def check_channel_signal_request(
        self, channel: paramiko.Channel, signame: str
    ) -> bool:
        self.signals.append(signame)
        return True

    @staticmethod
    def _shell(channel: paramiko.Channel) -> None:
        try:
            channel.sendall(b"$ ")
            while not channel.closed:
                if channel.recv_ready():
                    channel.recv(256)
                else:
                    time.sleep(0.05)
        except Exception:  # noqa: BLE001
            pass
        finally:
            with contextlib.suppress(Exception):
                channel.close()


class KeyboardInteractiveServer(paramiko.ServerInterface):
    """Keyboard-interactive server with configurable prompts and expected answers.

    Args:
        prompts: list of (label, echo) tuples — one entry per prompt shown to the client
        answers: expected correct answers in the same order as *prompts*
        name: challenge name forwarded to the client
        instructions: instructions forwarded to the client
    """

    def __init__(
        self,
        prompts: list[tuple[str, bool]],
        answers: list[str],
        name: str = "",
        instructions: str = "",
    ) -> None:
        self._prompts = prompts
        self._answers = answers
        self._name = name
        self._instructions = instructions

    def get_allowed_auths(self, username: str) -> str:
        return "keyboard-interactive"

    def check_auth_none(self, username: str) -> int:
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: str
    ) -> paramiko.server.InteractiveQuery:
        query = paramiko.server.InteractiveQuery(self._name, self._instructions)
        for label, echo in self._prompts:
            query.add_prompt(label, echo)
        return query

    def check_auth_interactive_response(self, responses: list[str]) -> int:
        if list(responses) == self._answers:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

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

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True


class IterativeKbdintServer(paramiko.ServerInterface):
    """Keyboard-interactive server that sends prompts in sequential rounds.

    Each :class:`KbdintRound` is a separate ``SSH_MSG_USERAUTH_INFO_REQUEST``
    message.  The server waits for the client's response before sending the
    next round.  Every round may carry a different number of prompts (RFC 4256
    allows zero or more per round).

    Example — two rounds, two prompts each::

        server = IterativeKbdintServer(rounds=[
            KbdintRound(
                prompts=[("OTP Token: ", True), ("PIN: ", False)],
                answers=["123456", "9876"],
                name="Step 1",
            ),
            KbdintRound(
                prompts=[("Password: ", False)],
                answers=["secret"],
                name="Step 2",
            ),
        ])
    """

    def __init__(self, rounds: list[KbdintRound]) -> None:
        self._rounds = rounds
        self._current = 0

    def get_allowed_auths(self, username: str) -> str:
        return "keyboard-interactive"

    def check_auth_none(self, username: str) -> int:
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: str
    ) -> paramiko.server.InteractiveQuery:
        self._current = 0
        return _make_round_query(self._rounds[0])

    def check_auth_interactive_response(
        self, responses: list[str]
    ) -> int | paramiko.server.InteractiveQuery:
        round_ = self._rounds[self._current]
        if list(responses) != round_.answers:
            return paramiko.common.AUTH_FAILED
        self._current += 1
        if self._current < len(self._rounds):
            return _make_round_query(self._rounds[self._current])
        return paramiko.common.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

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

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True


class MockServerInterface(paramiko.ServerInterface):
    """Full-featured server supporting all four auth methods.

    Used by ``python -m sshmitm.mockserver`` for interactive CLI use.
    """

    def __init__(
        self,
        username: str,
        password: str | None,
        pubkeys: list[paramiko.PKey],
        allow_none: bool,
    ) -> None:
        self._username = username
        self._password = password
        self._pubkeys = pubkeys
        self._allow_none = allow_none

    def get_allowed_auths(self, username: str) -> str:
        if username != self._username:
            return "publickey"
        methods: list[str] = []
        if self._allow_none:
            methods.append("none")
        if self._pubkeys:
            methods.append("publickey")
        if self._password is not None:
            methods += ["password", "keyboard-interactive"]
        return ",".join(methods) if methods else "publickey"

    def check_auth_none(self, username: str) -> int:
        if username == self._username and self._allow_none:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        if (
            username == self._username
            and self._password is not None
            and password == self._password
        ):
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if username != self._username:
            return paramiko.common.AUTH_FAILED
        for authorized in self._pubkeys:
            if key.get_base64() == authorized.get_base64():
                return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: bytes | str
    ) -> int | paramiko.server.InteractiveQuery:
        del submethods
        if username != self._username or self._password is None:
            return paramiko.common.AUTH_FAILED
        query = paramiko.server.InteractiveQuery("", "")
        query.add_prompt("Password: ", False)
        return query

    def check_auth_interactive_response(self, responses: list[str]) -> int:
        if responses and self._password is not None and responses[0] == self._password:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

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
        del channel, term, width, height, pixelwidth, pixelheight, modes
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        threading.Thread(target=_run_shell, args=(channel,), daemon=True).start()
        return True

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes
    ) -> bool:
        threading.Thread(target=_run_exec, args=(channel, command), daemon=True).start()
        return True

    def check_channel_forward_agent_request(self, channel: paramiko.Channel) -> bool:
        del channel
        return True


class MultiUserMockServer(paramiko.ServerInterface):
    """Mock server that maps different usernames to different auth methods.

    Each entry in *users* configures what a specific username may use to
    authenticate.  Build entries with the class-level factory helpers::

        server = MultiUserMockServer({
            "none":  MultiUserMockServer.none_user(),
            "pw":    MultiUserMockServer.password_user("s3cr3t"),
            "key":   MultiUserMockServer.pubkey_user([my_key]),
            "kbd":   MultiUserMockServer.kbdint_user(
                         prompts=[("OTP: ", True), ("Password: ", False)],
                         answers=["123456", "secret"],
                     ),
            "iter":  MultiUserMockServer.kbdint_iterative_user([
                         KbdintRound(prompts=[("OTP: ", True)],    answers=["123456"]),
                         KbdintRound(prompts=[("Password: ", False)], answers=["secret"]),
                     ]),
        })
    """

    def __init__(self, users: dict[str, _UserConfig]) -> None:
        self._users = users
        self._kbdint_username: str | None = None
        self._kbdint_round: int = 0

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @staticmethod
    def none_user() -> _UserConfig:
        return _UserConfig(allow_none=True)

    @staticmethod
    def password_user(password: str) -> _UserConfig:
        return _UserConfig(password=password)

    @staticmethod
    def pubkey_user(pubkeys: list[paramiko.PKey]) -> _UserConfig:
        return _UserConfig(pubkeys=pubkeys)

    @staticmethod
    def kbdint_user(
        prompts: list[tuple[str, bool]],
        answers: list[str],
        *,
        name: str = "",
        instructions: str = "",
    ) -> _UserConfig:
        """Single-round keyboard-interactive: all prompts sent at once."""
        return _UserConfig(
            kbdint_prompts=prompts,
            kbdint_answers=answers,
            kbdint_name=name,
            kbdint_instructions=instructions,
        )

    @staticmethod
    def kbdint_iterative_user(rounds: list[KbdintRound]) -> _UserConfig:
        """Multi-round keyboard-interactive: one round per SSH_MSG_USERAUTH_INFO_REQUEST."""
        return _UserConfig(kbdint_rounds=rounds)

    # ------------------------------------------------------------------
    # ServerInterface implementation
    # ------------------------------------------------------------------

    def get_allowed_auths(self, username: str) -> str:
        cfg = self._users.get(username)
        if cfg is None:
            return "publickey"
        methods: list[str] = []
        if cfg.allow_none:
            methods.append("none")
        if cfg.pubkeys:
            methods.append("publickey")
        if cfg.password is not None:
            methods.append("password")
        if cfg.kbdint_prompts or cfg.kbdint_rounds:
            methods.append("keyboard-interactive")
        return ",".join(methods) if methods else "publickey"

    def check_auth_none(self, username: str) -> int:
        cfg = self._users.get(username)
        if cfg and cfg.allow_none:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        cfg = self._users.get(username)
        if cfg and cfg.password is not None and password == cfg.password:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        cfg = self._users.get(username)
        if cfg is None:
            return paramiko.common.AUTH_FAILED
        for authorized in cfg.pubkeys:
            if key.get_base64() == authorized.get_base64():
                return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: bytes | str
    ) -> int | paramiko.server.InteractiveQuery:
        del submethods
        cfg = self._users.get(username)
        if cfg is None or (not cfg.kbdint_prompts and not cfg.kbdint_rounds):
            return paramiko.common.AUTH_FAILED
        self._kbdint_username = username
        self._kbdint_round = 0
        if cfg.kbdint_rounds:
            return _make_round_query(cfg.kbdint_rounds[0])
        query = paramiko.server.InteractiveQuery(cfg.kbdint_name, cfg.kbdint_instructions)
        for label, echo in cfg.kbdint_prompts:
            query.add_prompt(label, echo)
        return query

    def check_auth_interactive_response(
        self, responses: list[str]
    ) -> int | paramiko.server.InteractiveQuery:
        cfg = self._users.get(self._kbdint_username or "")
        if cfg is None:
            return paramiko.common.AUTH_FAILED
        if cfg.kbdint_rounds:
            round_ = cfg.kbdint_rounds[self._kbdint_round]
            if list(responses) != round_.answers:
                return paramiko.common.AUTH_FAILED
            self._kbdint_round += 1
            if self._kbdint_round < len(cfg.kbdint_rounds):
                return _make_round_query(cfg.kbdint_rounds[self._kbdint_round])
            return paramiko.common.AUTH_SUCCESSFUL
        if cfg.kbdint_answers and list(responses) == cfg.kbdint_answers:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

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
        del channel, term, width, height, pixelwidth, pixelheight, modes
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        threading.Thread(target=_run_shell, args=(channel,), daemon=True).start()
        return True

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes
    ) -> bool:
        threading.Thread(target=_run_exec, args=(channel, command), daemon=True).start()
        return True

    def check_channel_forward_agent_request(self, channel: paramiko.Channel) -> bool:
        del channel
        return True


def _make_round_query(round_: KbdintRound) -> paramiko.server.InteractiveQuery:
    query = paramiko.server.InteractiveQuery(round_.name, round_.instructions)
    for label, echo in round_.prompts:
        query.add_prompt(label, echo)
    return query


def _run_exec(channel: paramiko.Channel, command: bytes) -> None:
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603
            shlex.split(command.decode("utf-8", errors="replace")),
            capture_output=True,
            timeout=30,
            check=False,
        )
        channel.sendall(result.stdout)
        if result.stderr:
            channel.sendall_stderr(result.stderr)
        channel.send_exit_status(result.returncode)
    except Exception as exc:  # noqa: BLE001
        channel.sendall_stderr(f"mock-server exec error: {exc}\n".encode())
        channel.send_exit_status(1)
    finally:
        channel.close()


def _run_shell(channel: paramiko.Channel) -> None:
    try:
        channel.sendall(b"$ ")
        buf = b""
        while True:
            data = channel.recv(256)
            if not data:
                break
            channel.sendall(data)
            buf += data
            if b"\n" in buf or b"\r" in buf:
                cmd = buf.strip()
                buf = b""
                if cmd in (b"exit", b"logout", b"quit"):
                    break
                if not cmd:
                    channel.sendall(b"$ ")
                    continue
                try:
                    result = subprocess.run(  # noqa: S603  # nosec B603
                        shlex.split(cmd.decode("utf-8", errors="replace")),
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if result.stdout:
                        channel.sendall(result.stdout)
                    if result.stderr:
                        channel.sendall(result.stderr)
                except Exception as exc:  # noqa: BLE001
                    channel.sendall(f"error: {exc}\n".encode())
                channel.sendall(b"$ ")
    except Exception:  # noqa: BLE001, S110  # nosec B110
        pass
    finally:
        channel.send_exit_status(0)
        channel.close()
