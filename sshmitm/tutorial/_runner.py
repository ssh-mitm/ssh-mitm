"""Tutorial execution engine: manages mock server and evaluates step conditions."""

from __future__ import annotations

import base64
import hashlib
import json
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
        on_alert: Callable[[dict], None] | None = None,
    ) -> None:
        self._tutorial = tutorial
        self._on_step_complete = on_step_complete
        self._on_auth_event = on_auth_event
        self._on_alert = on_alert

        self.state = TutorialState.IDLE
        self.current_step = 0
        self.credentials: dict[str, str | int] = {}

        self._cancel = threading.Event()
        self._auth_events: list[tuple[str, bool]] = []
        self._auth_lock = threading.Lock()
        self._user_input: str | None = None
        self._input_lock = threading.Lock()
        self._auto_connect_fired = False
        self._mock_stop: threading.Event | None = None
        self._mock_closed: threading.Event | None = None
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

    def submit_input(self, text: str) -> bool:
        step = self._tutorial.steps[self.current_step] if self.current_step < len(self._tutorial.steps) else None
        if step is None:
            return False
        m = re.fullmatch(r'USER_INPUT\("([^"]+)"\)', step.condition.strip())
        if not m:
            return False
        expected = str(self.credentials.get(m.group(1), ""))
        correct = text.strip() == expected
        with self._input_lock:
            self._user_input = text.strip() if correct else None
        return correct

    def _poll(self, cancel: threading.Event) -> None:
        while not cancel.is_set():
            if self.state == TutorialState.RUNNING:
                if self.current_step < len(self._tutorial.steps):
                    step = self._tutorial.steps[self.current_step]
                    if step.auto_connect and not self._auto_connect_fired:
                        self._auto_connect_fired = True
                        threading.Thread(target=self._run_auto_client, daemon=True).start()
                    if self._eval(step.condition):
                        self._auto_connect_fired = False
                        self._complete_step()
                else:
                    self.state = TutorialState.COMPLETED
                    self._teardown()
            time.sleep(0.3)

    def _complete_step(self) -> None:
        idx = self.current_step
        self.current_step += 1
        with self._auth_lock:
            self._auth_events.clear()
        with self._input_lock:
            self._user_input = None
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

        m = re.fullmatch(r'USER_INPUT\("([^"]+)"\)', c)
        if m:
            key = m.group(1)
            expected = str(self.credentials.get(key, ""))
            with self._input_lock:
                return self._user_input is not None and self._user_input == expected

        _log.warning("unknown condition expression: %r", c)
        return False

    def _port_open(self, port: int) -> bool:
        hex_port = f"{port:04X}"
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path) as f:
                    next(f)
                    for line in f:
                        parts = line.split()
                        if len(parts) > 3 and parts[3] == "0A":
                            _, local_port = parts[1].rsplit(":", 1)
                            if local_port.upper() == hex_port:
                                return True
            except OSError:
                pass
        return False

    # ------------------------------------------------------------------
    # Mock server
    # ------------------------------------------------------------------

    def _setup_mock_server(self) -> None:
        combos = [f"{a}_{b}" for a in _ADJECTIVES for b in _BASE_NAMES]
        names = random.sample(combos, 2)
        none_user, auth_user = names[0], names[1]

        if self._tutorial.auth_type == "publickey":
            client_key = paramiko.ECDSAKey.generate()
            fp = _sha256_fingerprint(client_key)
            users: dict[str, _UserConfig] = {
                none_user: MultiUserMockServer.none_user(),
                auth_user: MultiUserMockServer.pubkey_user([client_key]),
            }
            extra_creds: dict[str, str | int] = {
                "pubkey_user": auth_user,
                "pubkey_fingerprint": fp,
                "_client_key_type": "ecdsa",
                "_client_key_b64": client_key.get_base64(),
            }
        else:
            pw = _random_password()
            users = {
                none_user: MultiUserMockServer.none_user(),
                auth_user: MultiUserMockServer.password_user(pw),
            }
            extra_creds = {
                "password_user": auth_user,
                "password_value": pw,
            }

        def factory() -> _TutorialServer:
            return _TutorialServer(users, self._handle_auth_event)

        actual_port, stop, closed = start_server_thread(
            factory,
            host_key=paramiko.ECDSAKey.generate(),
            bind="127.0.0.1",
            port=self._tutorial.mock_port,
        )
        self._mock_stop = stop
        self._mock_closed = closed
        self.credentials = {
            "none_user": none_user,
            "mock_port": actual_port,
            "sshmitm_port": self._tutorial.sshmitm_port,
            **extra_creds,
        }

    def _run_auto_client(self) -> None:
        time.sleep(1.0)
        auth_type = self._tutorial.auth_type
        for attempt in range(5):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if auth_type == "publickey":
                    pkey = _load_client_key(self.credentials)
                    client.connect(
                        "127.0.0.1",
                        port=int(self.credentials["sshmitm_port"]),
                        username=str(self.credentials["pubkey_user"]),
                        pkey=pkey,
                        timeout=10.0,
                        allow_agent=True,
                        look_for_keys=False,
                    )
                    transport = client.get_transport()
                    if transport is not None:
                        chan = transport.open_session()
                        paramiko.agent.AgentRequestHandler(chan)
                        chan.close()
                else:
                    client.connect(
                        "127.0.0.1",
                        port=int(self.credentials["sshmitm_port"]),
                        username=str(self.credentials["password_user"]),
                        password=str(self.credentials["password_value"]),
                        timeout=10.0,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                client.close()
                return
            except Exception:
                if attempt < 4:
                    time.sleep(1.0)
                else:
                    _log.debug("auto-client failed after %d attempts", attempt + 1, exc_info=True)

    def _teardown(self) -> None:
        if self._mock_stop:
            self._mock_stop.set()
            if self._mock_closed:
                self._mock_closed.wait(timeout=2.0)
            self._mock_stop = None
            self._mock_closed = None
        if self._agent:
            self._agent.stop()
            self._agent = None

    def _handle_auth_event(self, method: str, username: str, ok: bool) -> None:
        with self._auth_lock:
            self._auth_events.append((method, ok))
        self._on_auth_event(method, username, ok)


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _load_client_key(credentials: dict) -> paramiko.PKey:
    b64 = str(credentials.get("_client_key_b64", ""))
    key_type = str(credentials.get("_client_key_type", "ecdsa"))
    data = base64.b64decode(b64)
    if key_type == "ecdsa":
        return paramiko.ECDSAKey(data=data)
    raise ValueError(f"unsupported key type: {key_type}")


