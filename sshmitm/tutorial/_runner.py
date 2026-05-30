"""Tutorial execution engine: manages mock server and evaluates step conditions."""

from __future__ import annotations

import logging
import random
import re
import secrets
import socket
import string
import threading
import time
from typing import Callable

import paramiko

from sshmitm.mockserver._agent import MockAgent
from sshmitm.mockserver._interfaces import MultiUserMockServer, _UserConfig
from sshmitm.mockserver._runner import start_server_thread
from sshmitm.tutorial._definitions import Tutorial

_log = logging.getLogger(__name__)

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


# ---------------------------------------------------------------------------
# Observable mock server
# ---------------------------------------------------------------------------

class _TutorialServer(MultiUserMockServer):
    def __init__(self, users: dict[str, _UserConfig], on_auth: Callable) -> None:
        super().__init__(users)
        self._on_auth = on_auth

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
    """Manages one tutorial session: mock server lifecycle + step conditions.

    Conditions are declarative strings evaluated by :meth:`_eval`:

    * ``"TRUE()"``                        — completes immediately
    * ``"PORT_OPEN(sshmitm_port)"``       — waits for a TCP port
    * ``'AUTH_EVENT("password", True)'``  — waits for an auth event
    """

    def __init__(
        self,
        tutorial: Tutorial,
        on_step_complete: Callable[[int], None],
        on_auth_event: Callable[[str, str, bool], None],
    ) -> None:
        self._tutorial = tutorial
        self._on_step_complete = on_step_complete
        self._on_auth_event = on_auth_event

        self.state = TutorialState.IDLE
        self.current_step = 0
        self.credentials: dict[str, str | int] = {}

        self._cancel = threading.Event()
        self._auth_events: list[tuple[str, bool]] = []
        self._auth_lock = threading.Lock()
        self._mock_stop: threading.Event | None = None
        self._agent: MockAgent | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._cancel.clear()
        self.current_step = 0
        self.state = TutorialState.RUNNING
        self._setup_mock_server()
        threading.Thread(target=self._poll, args=(self._cancel,), daemon=True).start()

    def stop(self) -> None:
        self._cancel.set()
        self.state = TutorialState.STOPPED
        self._teardown()

    def format(self, text: str) -> str:
        try:
            return text.format(**self.credentials)
        except KeyError:
            return text

    # ------------------------------------------------------------------
    # Poll loop — single thread, evaluates current step condition
    # ------------------------------------------------------------------

    def _poll(self, cancel: threading.Event) -> None:
        while not cancel.is_set():
            if self.state == TutorialState.RUNNING:
                if self.current_step < len(self._tutorial.steps):
                    step = self._tutorial.steps[self.current_step]
                    if self._eval(step.condition):
                        self._complete_step()
                else:
                    self.state = TutorialState.COMPLETED
            time.sleep(0.3)

    def _complete_step(self) -> None:
        idx = self.current_step
        self.current_step += 1
        with self._auth_lock:
            self._auth_events.clear()
        if self.current_step >= len(self._tutorial.steps):
            self.state = TutorialState.COMPLETED
        self._on_step_complete(idx)

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------

    def _eval(self, condition: str) -> bool:
        c = condition.strip()

        if c == "TRUE()":
            return True

        m = re.fullmatch(r"PORT_OPEN\((\w+)\)", c)
        if m:
            port = int(self.credentials.get(m.group(1), 0))
            return self._port_open(port)

        m = re.fullmatch(r'AUTH_EVENT\("([^"]+)",\s*(True|False)\)', c)
        if m:
            method, success = m.group(1), m.group(2) == "True"
            with self._auth_lock:
                return any(met == method and ok == success for met, ok in self._auth_events)

        _log.warning("unknown condition expression: %r", c)
        return False

    def _port_open(self, port: int) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Mock server
    # ------------------------------------------------------------------

    def _setup_mock_server(self) -> None:
        pw = _random_password()
        mock_port = self._tutorial.mock_port
        combos = [f"{a}_{b}" for a in _ADJECTIVES for b in _BASE_NAMES]
        names = random.sample(combos, 2)
        none_user, password_user = names[0], names[1]

        users: dict[str, _UserConfig] = {
            none_user: MultiUserMockServer.none_user(),
            password_user: MultiUserMockServer.password_user(pw),
        }
        self.credentials = {
            "none_user": none_user,
            "password_user": password_user,
            "password_value": pw,
            "mock_port": mock_port,
            "sshmitm_port": self._tutorial.sshmitm_port,
        }

        def factory() -> _TutorialServer:
            return _TutorialServer(users, self._handle_auth_event)

        _, stop = start_server_thread(
            factory,
            host_key=paramiko.RSAKey.generate(2048),
            bind="127.0.0.1",
            port=mock_port,
        )
        self._mock_stop = stop

    def _teardown(self) -> None:
        if self._mock_stop:
            self._mock_stop.set()
            self._mock_stop = None
        if self._agent:
            self._agent.stop()
            self._agent = None

    def _handle_auth_event(self, method: str, username: str, ok: bool) -> None:
        with self._auth_lock:
            self._auth_events.append((method, ok))
        self._on_auth_event(method, username, ok)
