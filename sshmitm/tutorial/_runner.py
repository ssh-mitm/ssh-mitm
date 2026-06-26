"""Tutorial execution engine: manages mock server lifecycle and evaluates step conditions."""

from __future__ import annotations

import base64
import hashlib
import logging
import random
import secrets
import string
import threading
import time
from typing import Callable

import paramiko

from sshmitm.mockserver._interfaces import MultiUserMockServer, _UserConfig
from sshmitm.mockserver._runner import start_server_thread
from sshmitm.tutorial._conditions import collect_user_inputs, has_continue
from sshmitm.tutorial._context import AuthEventData, TutorialContext
from sshmitm.tutorial._definitions import Tutorial
from sshmitm.tutorial._server_config import (
    KeyboardInteractiveAuth,
    NoneAuth,
    PasswordAuth,
    PublicKeyAuth,
    TargetServerConfig,
)

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mock interactive shell
# ---------------------------------------------------------------------------

class _MockShell:
    """Fake interactive shell backed by an in-memory command→output dict.

    Does not spawn any subprocess.  Input is echoed back line-by-line;
    recognised commands return their predefined output, everything else
    gets an "unknown command" reply.  The prompt and unknown-command
    message are configurable so tutorials can impersonate any device
    (router, switch, database console, etc.).
    """

    def __init__(
        self,
        channel: paramiko.Channel,
        outputs: dict[str, bytes],
        prompt: bytes = b"$ ",
        unknown: bytes | None = None,
    ) -> None:
        self._channel = channel
        self._outputs = outputs
        self._prompt = prompt
        self._unknown = unknown  # None → derive from command name

    def run(self) -> None:
        try:
            self._channel.sendall(self._prompt)
            buf: bytearray = bytearray()
            in_escape = False
            while True:
                data = self._channel.recv(256)
                if not data:
                    break
                for byte in data:
                    if in_escape:
                        # Skip until end of ANSI escape sequence (0x40–0x7e)
                        if 0x40 <= byte <= 0x7E:
                            in_escape = False
                        continue
                    if byte == 0x1B:  # ESC
                        in_escape = True
                    elif byte in (0x0D, 0x0A):  # CR / LF → execute line
                        self._channel.sendall(b"\r\n")
                        cmd = buf.decode("utf-8", errors="replace").strip()
                        buf.clear()
                        if cmd in ("exit", "quit", "logout"):
                            return
                        if cmd:
                            self._channel.sendall(self._response(cmd))
                        self._channel.sendall(self._prompt)
                    elif byte in (0x7F, 0x08):  # DEL / Backspace
                        if buf:
                            buf.pop()
                            self._channel.sendall(b"\x08 \x08")
                    elif byte == 0x03:  # Ctrl+C
                        self._channel.sendall(b"^C\r\n")
                        buf.clear()
                        self._channel.sendall(self._prompt)
                    elif 0x20 <= byte < 0x7F:  # printable ASCII
                        buf.append(byte)
                        self._channel.sendall(bytes([byte]))
        except Exception:  # noqa: BLE001
            pass
        finally:
            with __import__("contextlib").suppress(Exception):
                self._channel.send_exit_status(0)
                self._channel.close()

    def _response(self, cmd: str) -> bytes:
        output = self._outputs.get(cmd)
        if output is not None:
            return output
        if self._unknown is not None:
            return self._unknown
        return f"% Unknown command: {cmd}\r\n".encode()

_ADJECTIVES = [
    "brave", "calm", "clever", "daring", "eager",
    "fierce", "gentle", "happy", "jolly", "keen",
    "lucky", "merry", "nimble", "proud", "quiet",
    "swift", "witty", "bold", "epic", "funky",
]
_BASE_NAMES = [
    "alice", "bob", "charlie", "dave", "eve",
    "frank", "grace", "henry", "ivan", "judy",
    "kate", "leo", "mallory", "nina", "oscar",
]


def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _random_username() -> str:
    combos = [f"{a}_{b}" for a in _ADJECTIVES for b in _BASE_NAMES]
    return random.choice(combos)


def _sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Observable mock server
# ---------------------------------------------------------------------------

class _TutorialServer(MultiUserMockServer):
    """MultiUserMockServer with auth-event callbacks and a virtual exec filesystem.

    Commands registered in *exec_outputs* return their predefined output without
    any subprocess being spawned.  Unregistered commands receive an empty response
    with exit status 1 — real execution is intentionally disabled for the tutorial
    mock server.
    """

    def __init__(
        self,
        users: dict[str, _UserConfig],
        on_auth: Callable,
        exec_outputs: dict[str, bytes] | None = None,
        shell_outputs: dict[str, bytes] | None = None,
        shell_prompt: bytes = b"$ ",
    ) -> None:
        super().__init__(users)
        self._on_auth = on_auth
        self._exec_outputs: dict[str, bytes] = exec_outputs or {}
        self._shell_outputs: dict[str, bytes] = shell_outputs or {}
        self._shell_prompt = shell_prompt

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes
    ) -> bool:
        cmd = command.decode("utf-8", errors="replace")
        output = self._exec_outputs.get(cmd, b"")
        threading.Thread(
            target=self._mock_exec, args=(channel, output), daemon=True
        ).start()
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        threading.Thread(
            target=_MockShell(channel, self._shell_outputs, self._shell_prompt).run,
            daemon=True,
        ).start()
        return True

    @staticmethod
    def _mock_exec(channel: paramiko.Channel, output: bytes) -> None:
        try:
            if output:
                channel.sendall(output)
            channel.send_exit_status(0 if output else 1)
        finally:
            channel.close()

    def _notify(self, method: str, username: str, result: int) -> None:
        ok = result == paramiko.common.AUTH_SUCCESSFUL
        self._on_auth(method, username, ok)

    def check_auth_none(self, username: str) -> int:
        result = super().check_auth_none(username)
        self._notify("none", username, result)
        return result

    def check_auth_password(self, username: str, password: str) -> int:
        result = super().check_auth_password(username, password)
        self._notify("password", username, result)
        return result

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        result = super().check_auth_publickey(username, key)
        self._notify("publickey", username, result)
        return result

    def check_auth_interactive_response(
        self, responses: list[str]
    ) -> "int | paramiko.server.InteractiveQuery":
        result = super().check_auth_interactive_response(responses)
        if isinstance(result, int):
            self._notify("keyboard-interactive", self._kbdint_username or "?", result)
        return result


# ---------------------------------------------------------------------------
# Runner state
# ---------------------------------------------------------------------------

class TutorialState:
    IDLE      = "idle"
    RUNNING   = "running"
    COMPLETED = "completed"
    STOPPED   = "stopped"


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

class TutorialRunner:
    """Manages one tutorial session: mock server lifecycle + step-condition polling.

    All public attributes that :mod:`sshmitm.tutorial._web` reads are
    preserved for backward compatibility:

    * ``state``       — current :class:`TutorialState` string
    * ``current_step``— zero-based index of the active step
    * ``tutorial_session_data`` — dict of runtime values (ports, users, passwords, …)
    * ``format(text)``— substitute ``{variable}`` placeholders
    * ``submit_input(key, value)`` — validate a user-submitted answer
    * ``acknowledge()``— mark the current step as acknowledged (Continue button)
    """

    def __init__(
        self,
        tutorial: Tutorial,
        on_step_complete: Callable[[int], None],
        on_auth_event: Callable[[str, str, bool], None],
        on_alert: Callable[[dict], None] | None = None,
        on_state_update: Callable[[], None] | None = None,
    ) -> None:
        self._tutorial = tutorial
        self._on_step_complete = on_step_complete
        self._on_auth_event = on_auth_event
        self._on_alert = on_alert
        # Called whenever runner state changes without a step completing
        # (e.g. condition becomes ready / unready).
        self._on_state_update = on_state_update or (lambda: None)

        self.state = TutorialState.IDLE
        self.current_step = 0

        self._ctx = TutorialContext({})
        self._cancel = threading.Event()
        self._auth_lock = threading.Lock()
        self._victim_fired = False
        self._step_ready = False   # True when condition is satisfied; user must click Continue
        self._prev_ready = False   # last broadcast value; reset on step change so re-broadcast fires
        self._mock_stop: threading.Event | None = None
        self._mock_closed: threading.Event | None = None
        self._target_stops: list[tuple[threading.Event, threading.Event]] = []
        self._git_server: object | None = None

    # ------------------------------------------------------------------
    # Backward-compat property used by _web.py
    # ------------------------------------------------------------------

    @property
    def tutorial_session_data(self) -> dict[str, object]:
        return self._ctx.tutorial_session_data

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._cancel.clear()
        self.current_step = 0
        self.state = TutorialState.RUNNING
        self._setup_mock_server()
        self._activate_step(0)
        threading.Thread(target=self._poll, args=(self._cancel,), daemon=True).start()

    def stop(self) -> None:
        self._cancel.set()
        self.state = TutorialState.STOPPED
        self._teardown()

    def format(self, text: str) -> str:
        try:
            return text.format(**self._ctx.tutorial_session_data)
        except KeyError:
            return text

    def submit_input(self, key: str, value: str) -> bool:
        """Validate *value* for the credential *key*.

        Stores the value in the context if correct so that the condition can
        pick it up on the next poll.  Returns True on correct input.
        """
        expected = str(self._ctx.tutorial_session_data.get(key, ""))
        correct = value.strip() == expected
        if correct:
            self._ctx.user_inputs[key] = value.strip()
        else:
            self._ctx.user_inputs.pop(key, None)
        return correct

    def advance(self) -> bool:
        """Advance to the next step — only allowed when the condition is satisfied.

        Sets ``ctx.acknowledged`` before re-evaluating so that a
        :class:`~sshmitm.tutorial._conditions.Continue` condition in the
        current step is satisfied by this click.
        """
        if self.state != TutorialState.RUNNING:
            return False
        steps = self._tutorial.steps
        if self.current_step >= len(steps):
            return False
        self._ctx.acknowledged = True
        self._step_ready = bool(steps[self.current_step].condition(self._ctx))
        if not self._step_ready:
            self._on_state_update()
            return False
        self._complete_step()
        return True

    def is_step_ready(self) -> bool:
        return self._step_ready

    def get_step_hint(self, step_idx: int) -> tuple[str, str]:
        """Return (hint_text, hint_type) for the given step index.

        For the active step, a dynamic ``hint_override`` from the context
        takes precedence over the static ``hint_waiting`` text.
        """
        steps = self._tutorial.steps
        if step_idx >= len(steps):
            return "", "info"
        step = steps[step_idx]
        current = self.current_step
        if step_idx < current:
            return self.format(step.hint_done), "info"
        if step_idx == current:
            override = self._ctx.hint_override
            if override:
                return self.format(override), self._ctx.hint_override_type
            if self._step_ready and step.hint_done:
                return self.format(step.hint_done), "info"
            return self.format(step.hint_waiting) if step.hint_waiting else "", "info"
        return "", "info"

    def get_active_user_inputs(self) -> list[dict[str, str]]:
        """Return the UserInput prompts for the current step.

        Each entry is ``{"key": ..., "prompt": ..., "satisfied": bool}``.
        Used by the web server to render input fields.
        """
        steps = self._tutorial.steps
        if self.current_step >= len(steps):
            return []
        condition = steps[self.current_step].condition
        result = []
        for ui in collect_user_inputs(condition):
            result.append({
                "key": ui.key,
                "prompt": ui.prompt,
                "satisfied": self._ctx.user_inputs.get(ui.key)
                             == str(self._ctx.tutorial_session_data.get(ui.key, "")),
            })
        return result

    # ------------------------------------------------------------------
    # Poll loop
    # ------------------------------------------------------------------

    def _poll(self, cancel: threading.Event) -> None:
        while not cancel.is_set():
            if self.state == TutorialState.RUNNING:
                steps = self._tutorial.steps
                if self.current_step < len(steps):
                    step = steps[self.current_step]
                    if step.victim_action and not self._victim_fired:
                        self._victim_fired = True
                        threading.Thread(
                            target=step.victim_action.run,
                            args=(self._ctx,),
                            daemon=True,
                        ).start()
                    ready = bool(step.condition(self._ctx))
                    self._step_ready = ready
                    if ready != self._prev_ready:
                        self._prev_ready = ready
                        self._on_state_update()
                elif self.state != TutorialState.COMPLETED:
                    self.state = TutorialState.COMPLETED
                    self._teardown()
            time.sleep(0.3)

    def _activate_step(self, idx: int) -> None:
        """Reset per-step state and call reset() on the step's condition."""
        self._victim_fired = False
        self._ctx.clear_step_state()
        steps = self._tutorial.steps
        if idx < len(steps):
            cond = steps[idx].condition
            if hasattr(cond, "reset"):
                cond.reset()  # type: ignore[union-attr]

    def _complete_step(self) -> None:
        idx = self.current_step
        self.current_step += 1
        self._step_ready = False
        self._prev_ready = False  # ensure next poll broadcasts even if condition is immediately True
        self._activate_step(self.current_step)
        if self.current_step >= len(self._tutorial.steps):
            self.state = TutorialState.COMPLETED
        self._on_step_complete(idx)

    # ------------------------------------------------------------------
    # Mock server setup
    # ------------------------------------------------------------------

    def _setup_mock_server(self) -> None:
        extra = self._tutorial.generate_tutorial_session_data()
        server_cfg = self._tutorial.get_server()
        users: dict[str, _UserConfig] = {}
        session_data: dict[str, object] = {
            "mock_port": server_cfg.mock_port,
            "sshmitm_port": server_cfg.sshmitm_port,
            **extra,
        }

        used_names: set[str] = set()

        for user_cfg in server_cfg.users:
            username = user_cfg.username or _unique_username(used_names)
            used_names.add(username)
            auth = user_cfg.auth

            if isinstance(auth, PasswordAuth):
                pw = auth.password or _random_password()
                users[username] = MultiUserMockServer.password_user(pw)
                session_data.setdefault("password_user", username)
                session_data.setdefault("password_value", pw)

            elif isinstance(auth, PublicKeyAuth):
                key = auth.key or paramiko.ECDSAKey.generate()
                users[username] = MultiUserMockServer.pubkey_user([key])
                session_data.setdefault("pubkey_user", username)
                session_data.setdefault("pubkey_fingerprint", _sha256_fingerprint(key))
                session_data.setdefault("_client_key", key)

            elif isinstance(auth, NoneAuth):
                users[username] = MultiUserMockServer.none_user()
                session_data.setdefault("none_user", username)

            elif isinstance(auth, KeyboardInteractiveAuth):
                users[username] = MultiUserMockServer.kbdint_iterative_user(auth.rounds)
                session_data.setdefault("kbdint_user", username)

        exec_outputs = self._tutorial.generate_exec_outputs(session_data) or None
        shell_outputs = self._tutorial.generate_shell_outputs(session_data) or None
        shell_prompt = self._tutorial.shell_prompt()

        def factory() -> _TutorialServer:
            return _TutorialServer(
                users,
                self._handle_auth_event,
                exec_outputs=exec_outputs,
                shell_outputs=shell_outputs,
                shell_prompt=shell_prompt,
            )

        sftp_files = self._tutorial.generate_sftp_files(session_data) or None
        actual_port, stop, closed = start_server_thread(
            factory,
            host_key=paramiko.ECDSAKey.generate(),
            bind="127.0.0.1",
            port=server_cfg.mock_port,
            sftp_files=sftp_files,
        )
        self._mock_stop = stop
        self._mock_closed = closed
        session_data["mock_port"] = actual_port

        self._setup_target_servers(session_data)
        self._setup_git_server(session_data)

        self._ctx = TutorialContext(session_data)

    def _setup_target_servers(self, session_data: dict[str, object]) -> None:
        """Start additional target SSH servers defined by the tutorial."""
        self._target_stops = []
        for target_cfg in self._tutorial.get_target_servers():
            users: dict[str, _UserConfig] = {}
            used_names: set[str] = set()
            for user_cfg in target_cfg.users:
                username = user_cfg.username or _unique_username(used_names)
                used_names.add(username)
                auth = user_cfg.auth
                if isinstance(auth, PasswordAuth):
                    pw = auth.password or _random_password()
                    users[username] = MultiUserMockServer.password_user(pw)
                elif isinstance(auth, PublicKeyAuth):
                    key = auth.key or paramiko.ECDSAKey.generate()
                    users[username] = MultiUserMockServer.pubkey_user([key])
                elif isinstance(auth, NoneAuth):
                    users[username] = MultiUserMockServer.none_user()
                elif isinstance(auth, KeyboardInteractiveAuth):
                    users[username] = MultiUserMockServer.kbdint_iterative_user(auth.rounds)

            captured_users = users

            def _factory(u: dict[str, _UserConfig] = captured_users) -> MultiUserMockServer:
                return MultiUserMockServer(u)

            actual_port, stop, closed = start_server_thread(
                _factory,
                host_key=paramiko.ECDSAKey.generate(),
                bind="127.0.0.1",
                port=target_cfg.port,
            )
            self._target_stops.append((stop, closed))
            session_data[f"{target_cfg.name}_port"] = actual_port

    def _setup_git_server(self, session_data: dict[str, object]) -> None:
        """Start the fake Git hosting server if the tutorial defines one."""
        git_cfg = self._tutorial.get_git_server()
        if git_cfg is None:
            return
        from sshmitm.tutorial.gitserver import GitServer
        srv = GitServer(git_cfg)
        srv.start()
        self._git_server = srv
        session_data["git_server_port"] = srv.port
        session_data["git_server_url"] = srv.url

    def _teardown(self) -> None:
        if self._mock_stop:
            self._mock_stop.set()
            if self._mock_closed:
                self._mock_closed.wait(timeout=2.0)
            self._mock_stop = None
            self._mock_closed = None
        for stop, closed in self._target_stops:
            stop.set()
            closed.wait(timeout=2.0)
        self._target_stops = []
        self._git_server = None

    def _handle_auth_event(self, method: str, username: str, ok: bool) -> None:
        with self._auth_lock:
            self._ctx.auth_events.append(AuthEventData(method, username, ok))
        self._on_auth_event(method, username, ok)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unique_username(used: set[str]) -> str:
    combos = [f"{a}_{b}" for a in _ADJECTIVES for b in _BASE_NAMES]
    random.shuffle(combos)
    for name in combos:
        if name not in used:
            return name
    return f"user_{secrets.token_hex(4)}"
