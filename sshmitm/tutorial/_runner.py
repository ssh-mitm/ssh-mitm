"""Tutorial execution engine: manages mock server lifecycle and evaluates step conditions."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

import paramiko

from sshmitm.mockserver._interfaces import MultiUserMockServer, _UserConfig
from sshmitm.mockserver._runner import start_server_thread
from sshmitm.tutorial._conditions import collect_user_inputs
from sshmitm.tutorial._context import AuthEventData, TutorialContext
from sshmitm.tutorial._definitions import Tutorial

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mock interactive shell
# ---------------------------------------------------------------------------

class _MockShell:
    """Fake interactive shell backed by an in-memory command→output dict."""

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
        self._unknown = unknown

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
                        if 0x40 <= byte <= 0x7E:
                            in_escape = False
                        continue
                    if byte == 0x1B:
                        in_escape = True
                    elif byte in (0x0D, 0x0A):
                        self._channel.sendall(b"\r\n")
                        cmd = buf.decode("utf-8", errors="replace").strip()
                        buf.clear()
                        if cmd in ("exit", "quit", "logout"):
                            return
                        if cmd:
                            self._channel.sendall(self._response(cmd))
                        self._channel.sendall(self._prompt)
                    elif byte in (0x7F, 0x08):
                        if buf:
                            buf.pop()
                            self._channel.sendall(b"\x08 \x08")
                    elif byte == 0x03:
                        self._channel.sendall(b"^C\r\n")
                        buf.clear()
                        self._channel.sendall(self._prompt)
                    elif 0x20 <= byte < 0x7F:
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


# ---------------------------------------------------------------------------
# Observable mock SSH server
# ---------------------------------------------------------------------------

class _TutorialServer(MultiUserMockServer):
    """MultiUserMockServer with auth-event callbacks and virtual exec/shell."""

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

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        cmd = command.decode("utf-8", errors="replace")
        output = self._exec_outputs.get(cmd, b"")
        threading.Thread(target=self._mock_exec, args=(channel, output), daemon=True).start()
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

    def check_auth_interactive_response(self, responses: list[str]) -> "int | paramiko.server.InteractiveQuery":
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
    """Manages one tutorial session: mock server lifecycle + step-condition polling."""

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
        self._on_state_update = on_state_update or (lambda: None)

        self.state = TutorialState.IDLE
        self.current_step = 0

        self._ctx = TutorialContext({})
        self._cancel = threading.Event()
        self._auth_lock = threading.Lock()
        self._victim_fired = False
        self._step_ready = False
        self._prev_ready = False
        self._mock_stop: threading.Event | None = None
        self._mock_closed: threading.Event | None = None
        self._target_stops: list[tuple[threading.Event, threading.Event]] = []
        self._service_hosts: list[Tutorial] = []  # hosts with start_services() running

    # ------------------------------------------------------------------
    # Backward-compat property
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
        expected = str(self._ctx.tutorial_session_data.get(key, ""))
        correct = value.strip() == expected
        if correct:
            self._ctx.user_inputs[key] = value.strip()
        else:
            self._ctx.user_inputs.pop(key, None)
        return correct

    def advance(self) -> bool:
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
        self._prev_ready = False
        self._activate_step(self.current_step)
        if self.current_step >= len(self._tutorial.steps):
            self.state = TutorialState.COMPLETED
        self._on_step_complete(idx)

    # ------------------------------------------------------------------
    # Mock server setup (new scenario-based API)
    # ------------------------------------------------------------------

    def _setup_mock_server(self) -> None:
        from sshmitm.tutorial._requirements import (
            NoneAuthAccess, RandomKeyPair, RandomPassword,
            RegisterPublicKeys, StaticKeyPair, StaticPassword,
        )
        from sshmitm.tutorial._session import ScenarioGenerator

        t = self._tutorial

        # Collect all host aliases: proxy target + direct targets
        all_aliases: dict[str, type] = {}
        if t.proxy_target is not None:
            all_aliases["proxy_target"] = t.proxy_target
        all_aliases.update(t.direct_targets)

        # Build ScenarioSession
        session = ScenarioGenerator.build(
            scenario     = t.scenario,
            host_aliases = all_aliases,
            requires     = t.requires,
            sshmitm_port = t.sshmitm_port,
        )

        # Flatten template vars into session_data
        session_data: dict[str, object] = dict(session.template_vars())

        # Merge tutorial-specific extra values (random choices, etc.)
        session_data.update(t.generate_tutorial_session_data())

        # Helper: build _UserConfig dict for one host from requires
        def users_for_host(host_cls: type) -> dict[str, _UserConfig]:
            users: dict[str, _UserConfig] = {}
            for req in t.requires:
                if isinstance(req, (RandomPassword, StaticPassword)) and req.host is host_cls:
                    pw = str(session_data.get(req.key, ""))
                    cfg = users.get(req.user.username)
                    if cfg is None:
                        cfg = MultiUserMockServer.password_user(pw)
                    else:
                        cfg.password = pw
                    users[req.user.username] = cfg
                elif isinstance(req, (RandomKeyPair, StaticKeyPair)):
                    if host_cls in req.authorized_on:
                        key = session_data.get(req.key_private)
                        if key:
                            cfg = users.get(req.user.username)
                            if cfg is None:
                                users[req.user.username] = MultiUserMockServer.pubkey_user([key])
                            else:
                                cfg.pubkeys.append(key)
                elif isinstance(req, NoneAuthAccess) and req.host is host_cls:
                    if req.user.username not in users:
                        users[req.user.username] = MultiUserMockServer.none_user()
            return users

        # ── Start proxy target mock SSH server ─────────────────────────
        if t.proxy_target is not None:
            proxy_inst = session.get_host("proxy_target")
            proxy_cls  = t.proxy_target
            users = users_for_host(proxy_cls)

            exec_out   = _call_behavior(proxy_inst, "exec_outputs", session_data)
            shell_out  = _call_behavior(proxy_inst, "shell_outputs", session_data)
            shell_pr   = proxy_inst.shell_prompt() if hasattr(proxy_inst, "shell_prompt") else b"$ "
            sftp_files = _call_behavior(proxy_inst, "sftp_files", session_data) or None

            def _proxy_factory(u=users, eo=exec_out, so=shell_out, sp=shell_pr) -> _TutorialServer:
                return _TutorialServer(u, self._handle_auth_event,
                                       exec_outputs=eo, shell_outputs=so, shell_prompt=sp)

            ssh_svc = proxy_inst.get_service("SSH") or proxy_inst.get_service("SFTP")
            port = ssh_svc.port if ssh_svc else 0

            actual, stop, closed = start_server_thread(
                _proxy_factory,
                host_key = paramiko.ECDSAKey.generate(),
                bind     = proxy_cls.address,
                port     = port,
                sftp_files = sftp_files,
            )
            self._mock_stop   = stop
            self._mock_closed = closed
            session_data["mock_port"] = actual

            # Also call start_services for the proxy host (e.g. HTTP on web01)
            extra = proxy_inst.start_services(session_data)
            session_data.update(extra)
            if extra:
                self._service_hosts.append(proxy_inst)  # type: ignore[arg-type]
        else:
            session_data.setdefault("mock_port", 0)

        # ── Start direct target servers ────────────────────────────────
        self._target_stops = []
        for alias, host_cls in t.direct_targets.items():
            host_inst = session.get_host(alias)

            # Non-SSH services (Git, HTTP, …) go through start_services()
            extra = host_inst.start_services(session_data)
            session_data.update(extra)
            if extra:
                self._service_hosts.append(host_inst)  # type: ignore[arg-type]

            # SSH/SFTP services → start a mock server
            ssh_svc = host_inst.get_service("SSH") or host_inst.get_service("SFTP")
            if ssh_svc is None:
                continue
            users = users_for_host(host_cls)
            if not users:
                continue

            def _target_factory(u=users) -> MultiUserMockServer:
                return MultiUserMockServer(u)

            actual, stop, closed = start_server_thread(
                _target_factory,
                host_key = paramiko.ECDSAKey.generate(),
                bind     = host_cls.address,
                port     = ssh_svc.port,
            )
            self._target_stops.append((stop, closed))
            session_data[f"{alias}_port"] = actual

        # ── Transitional: standalone git server (via get_git_server) ───
        git_cfg = t.get_git_server(session_data)
        if git_cfg is not None:
            from sshmitm.tutorial.gitserver import GitServer
            srv = GitServer(git_cfg)
            srv.start()
            self._git_server = srv
            session_data["git_server_port"] = srv.port
            session_data["git_server_url"]  = srv.url
        else:
            self._git_server = None

        # ── Bridge keys for client actions ─────────────────────────────
        self._bridge_client_action_keys(t, session_data)

        self._ctx = TutorialContext(session_data)

    def _bridge_client_action_keys(self, t: Tutorial, session_data: dict) -> None:
        """Set legacy credential keys used by client actions (SSHPasswordAction, etc.)."""
        from sshmitm.tutorial._requirements import RandomKeyPair, StaticKeyPair

        victim = t.victim
        proxy  = t.proxy_target
        if victim is None:
            return

        uname = victim.username

        # Password bridge
        if proxy is not None:
            pw_key = f"{proxy.label}_{uname}_password"
            if pw_key in session_data:
                session_data.setdefault("password_user", uname)
                session_data.setdefault("password_value", session_data[pw_key])

        # Pubkey bridge (first key authorized on proxy target)
        for req in t.requires:
            if isinstance(req, (RandomKeyPair, StaticKeyPair)) and req.user is victim:
                if proxy in req.authorized_on:
                    key = session_data.get(req.key_private)
                    fp  = session_data.get(req.key_fp)
                    if key:
                        session_data.setdefault("pubkey_user", uname)
                        session_data.setdefault("_client_key", key)
                    if fp:
                        session_data.setdefault("pubkey_fingerprint", fp)
                    break

        # None auth fallback
        session_data.setdefault("none_user", uname)

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def _teardown(self) -> None:
        if self._mock_stop:
            self._mock_stop.set()
            if self._mock_closed:
                self._mock_closed.wait(timeout=2.0)
            self._mock_stop   = None
            self._mock_closed = None
        for stop, closed in self._target_stops:
            stop.set()
            closed.wait(timeout=2.0)
        self._target_stops = []
        for host in self._service_hosts:
            try:
                host.stop_services()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass
        self._service_hosts = []
        self._git_server = None

    def _handle_auth_event(self, method: str, username: str, ok: bool) -> None:
        with self._auth_lock:
            self._ctx.auth_events.append(AuthEventData(method, username, ok))
        self._on_auth_event(method, username, ok)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call_behavior(host: object, method: str, session_data: dict) -> dict | None:
    """Call ``host.method(session_data)`` if the method exists, return result or None."""
    fn = getattr(host, method, None)
    if fn is not None:
        result = fn(session_data)
        return result if result else None
    return None
