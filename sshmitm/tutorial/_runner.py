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
from typing import Any, Callable

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
)

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
    """MultiUserMockServer extended with auth-event callbacks."""

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
    """Manages one tutorial session: mock server lifecycle + step-condition polling.

    All public attributes that :mod:`sshmitm.tutorial._web` reads are
    preserved for backward compatibility:

    * ``state``       — current :class:`TutorialState` string
    * ``current_step``— zero-based index of the active step
    * ``credentials`` — dict of runtime values (ports, users, passwords, …)
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

    # ------------------------------------------------------------------
    # Backward-compat property used by _web.py
    # ------------------------------------------------------------------

    @property
    def credentials(self) -> dict[str, Any]:
        return self._ctx.credentials

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
            return text.format(**self._ctx.credentials)
        except KeyError:
            return text

    def submit_input(self, key: str, value: str) -> bool:
        """Validate *value* for the credential *key*.

        Stores the value in the context if correct so that the condition can
        pick it up on the next poll.  Returns True on correct input.
        """
        expected = str(self._ctx.credentials.get(key, ""))
        correct = value.strip() == expected
        if correct:
            self._ctx.user_inputs[key] = value.strip()
        else:
            self._ctx.user_inputs.pop(key, None)
        return correct

    def advance(self) -> bool:
        """Advance to the next step — only allowed when the condition is satisfied.

        Returns True when the step was actually advanced.  The web server
        should call this when the user clicks the Continue button.
        """
        if self.state != TutorialState.RUNNING:
            return False
        if not self._step_ready:
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
                             == str(self._ctx.credentials.get(ui.key, "")),
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
        server_cfg = self._tutorial.get_server()
        users: dict[str, _UserConfig] = {}
        credentials: dict[str, Any] = {
            "mock_port": server_cfg.mock_port,
            "sshmitm_port": server_cfg.sshmitm_port,
        }

        used_names: set[str] = set()

        for user_cfg in server_cfg.users:
            username = user_cfg.username or _unique_username(used_names)
            used_names.add(username)
            auth = user_cfg.auth

            if isinstance(auth, PasswordAuth):
                pw = auth.password or _random_password()
                users[username] = MultiUserMockServer.password_user(pw)
                credentials.setdefault("password_user", username)
                credentials.setdefault("password_value", pw)

            elif isinstance(auth, PublicKeyAuth):
                key = auth.key or paramiko.ECDSAKey.generate()
                users[username] = MultiUserMockServer.pubkey_user([key])
                credentials.setdefault("pubkey_user", username)
                credentials.setdefault("pubkey_fingerprint", _sha256_fingerprint(key))
                credentials.setdefault("_client_key", key)

            elif isinstance(auth, NoneAuth):
                users[username] = MultiUserMockServer.none_user()
                credentials.setdefault("none_user", username)

            elif isinstance(auth, KeyboardInteractiveAuth):
                users[username] = MultiUserMockServer.kbdint_iterative_user(auth.rounds)
                credentials.setdefault("kbdint_user", username)

        def factory() -> _TutorialServer:
            return _TutorialServer(users, self._handle_auth_event)

        actual_port, stop, closed = start_server_thread(
            factory,
            host_key=paramiko.ECDSAKey.generate(),
            bind="127.0.0.1",
            port=server_cfg.mock_port,
        )
        self._mock_stop = stop
        self._mock_closed = closed
        credentials["mock_port"] = actual_port
        self._ctx = TutorialContext(credentials)

    def _teardown(self) -> None:
        if self._mock_stop:
            self._mock_stop.set()
            if self._mock_closed:
                self._mock_closed.wait(timeout=2.0)
            self._mock_stop = None
            self._mock_closed = None

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
