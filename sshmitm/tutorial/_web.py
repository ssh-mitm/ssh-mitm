"""Simple HTTP server for the SSH-MITM tutorial system."""

from __future__ import annotations

import html as _html
import signal
import http.server
import json
import logging
import os
import pathlib
import queue
import re
import socket
import socketserver
import tempfile
import threading
import time
import webbrowser
from datetime import datetime
from importlib import resources as _resources
from typing import TYPE_CHECKING

from sshmitm.tutorial._definitions import Tutorial
from sshmitm.tutorial._event_processor import process as process_event
from sshmitm.tutorial._progress import load_completed, mark_completed
from sshmitm.tutorial._runner import TutorialRunner, TutorialState

if TYPE_CHECKING:
    pass

_log = logging.getLogger(__name__)
_LOGO_PATH = pathlib.Path(__file__).parent.parent / "data" / "ssh-mitm-logo.png"
_STATIC = _resources.files("sshmitm.tutorial.static")

_STATIC_FILES: dict[str, str] = {
    "tutorial.html": "text/html; charset=utf-8",
    "tutorial.css": "text/css; charset=utf-8",
    "tutorial.js": "application/javascript; charset=utf-8",
}


def _read_static(name: str) -> bytes:
    return _STATIC.joinpath(name).read_bytes()


# ---------------------------------------------------------------------------
# Markdown → HTML  (covers what our tutorials actually use)
# ---------------------------------------------------------------------------

def _md_to_html(text: str) -> str:
    try:
        import markdown  # type: ignore[import-untyped]
        return markdown.markdown(text)
    except ImportError:
        pass
    return _simple_md(text)


def _simple_md(text: str) -> str:
    out: list[str] = []
    for para in re.split(r"\n{2,}", text.strip()):
        lines = para.strip().splitlines()
        if not lines:
            continue
        first = lines[0]
        if first.startswith("## "):
            out.append(f"<h2>{_inline(first[3:])}</h2>")
        elif first.startswith("### "):
            out.append(f"<h3>{_inline(first[4:])}</h3>")
        elif first.startswith("# "):
            out.append(f"<h1>{_inline(first[2:])}</h1>")
        elif first.strip() == "---":
            out.append("<hr>")
        else:
            block_lines = []
            for line in lines:
                if line.startswith("> "):
                    block_lines.append(f"<blockquote>{_inline(line[2:])}</blockquote>")
                else:
                    block_lines.append(_inline(line))
            out.append("<p>" + "<br>".join(block_lines) + "</p>")
    return "\n".join(out)


def _inline(text: str) -> str:
    text = _html.escape(text)
    text = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.*?)`", r"<code>\1</code>", text)
    return text


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        if self.path == "/":
            self._send(200, "text/html; charset=utf-8", _read_static("tutorial.html"))
        elif self.path == "/state":
            self._send(200, "application/json",
                       json.dumps(self.server.get_state()).encode())  # type: ignore[attr-defined]
        elif self.path == "/events":
            self._sse()
        elif self.path == "/logo.png":
            if _LOGO_PATH.exists():
                self._send(200, "image/png", _LOGO_PATH.read_bytes())
            else:
                self.send_response(404)
                self.end_headers()
        elif self.path.startswith("/static/"):
            name = self.path[8:]
            if name in _STATIC_FILES:
                self._send(200, _STATIC_FILES[name], _read_static(name))
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self) -> None:
        if self.path == "/action":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            action = body.get("action")
            if action == "submit_input":
                correct = self.server.submit_input(body.get("value", ""))  # type: ignore[attr-defined]
                self._send(200, "application/json",
                           json.dumps({"ok": True, "correct": correct}).encode())
            else:
                self.server.handle_action(action, body.get("tutorial_id"))  # type: ignore[attr-defined]
                self._send(200, "application/json", b'{"ok":true}')
        else:
            self.send_response(404)
            self.end_headers()

    def _send(self, code: int, ct: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        q: queue.Queue[dict] = queue.Queue()
        srv: TutorialWebServer = self.server  # type: ignore[assignment]
        srv.add_client(q)

        # send current state immediately
        try:
            self._sse_send(q, {"type": "state", "data": srv.get_state()})
            while True:
                try:
                    event = q.get(timeout=15)
                    self._sse_send(q, event)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            srv.remove_client(q)

    def _sse_send(self, _q: object, event: dict) -> None:
        data = json.dumps(event)
        self.wfile.write(f"data: {data}\n\n".encode())
        self.wfile.flush()

    def log_message(self, fmt: str, *args: object) -> None:
        _log.debug("HTTP %s", fmt % args)


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class TutorialWebServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def __init__(self, tutorials: list[Tutorial], port: int = 0) -> None:
        super().__init__(("127.0.0.1", port), _Handler)
        self._tutorials = tutorials
        self._selected: Tutorial | None = None
        self._runner: TutorialRunner | None = None
        self._completed: set[str] = load_completed()
        self._clients: list[queue.Queue[dict]] = []
        self._lock = threading.Lock()

        self._log_socket_path = os.path.join(
            tempfile.gettempdir(), "sshmitm-tutorial.sock"
        )
        self._log_socket: socket.socket | None = None
        self._sshmitm_socket_connected = False
        self._sshmitm_running = False
        self._start_log_socket()
        self._start_status_checker()

    # SSE client management

    def add_client(self, q: queue.Queue[dict]) -> None:
        with self._lock:
            self._clients.append(q)

    def remove_client(self, q: queue.Queue[dict]) -> None:
        with self._lock:
            try:
                self._clients.remove(q)
            except ValueError:
                pass

    # ------------------------------------------------------------------
    # Unix socket — receives structured log events from SSH-MITM
    # ------------------------------------------------------------------

    def _start_log_socket(self) -> None:
        if os.path.exists(self._log_socket_path):
            os.unlink(self._log_socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self._log_socket_path)
        sock.listen(5)
        sock.settimeout(1.0)
        self._log_socket = sock
        t = threading.Thread(target=self._log_accept_loop, daemon=True)
        t.start()

    @staticmethod
    def _port_open(port: int) -> bool:
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

    def _start_status_checker(self) -> None:
        t = threading.Thread(target=self._status_check_loop, daemon=True)
        t.start()

    def _status_check_loop(self) -> None:
        while True:
            time.sleep(2)
            with self._lock:
                tut = self._selected
                connected = self._sshmitm_socket_connected
                prev = self._sshmitm_running

            # Retry push to SSH-MITM whenever the socket connection is absent
            if not connected:
                _notify_sshmitm(self._log_socket_path)

            if tut is None:
                continue
            running = connected or self._port_open(tut.sshmitm_port)
            with self._lock:
                self._sshmitm_running = running
            if running != prev:
                self.broadcast("state", self.get_state())

    def _log_accept_loop(self) -> None:
        assert self._log_socket is not None
        while True:
            try:
                conn, _ = self._log_socket.accept()
                threading.Thread(
                    target=self._log_read_client, args=(conn,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _log_read_client(self, conn: socket.socket) -> None:
        with self._lock:
            self._sshmitm_socket_connected = True
            self._sshmitm_running = True
        self.broadcast("state", self.get_state())
        buf = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line:
                        try:
                            self._on_log_event(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        finally:
            conn.close()
            with self._lock:
                self._sshmitm_socket_connected = False
            self.broadcast("state", self.get_state())

    def _on_log_event(self, event: dict) -> None:
        with self._lock:
            runner = self._runner
        if event.get("event") and runner is not None:
            runner.add_log_event(event)
        display = process_event(event)
        if display is None:
            return
        # Forward alerts with hints (e.g. host-key errors) but suppress generic activity entries.
        if display.get("hint"):
            tut_events = {a.event for a in runner._tutorial.event_alerts} if runner else set()
            if event.get("event") not in tut_events:
                self.broadcast("alert", {
                    "title": display["title"],
                    "detail": display.get("detail"),
                    "hint": display["hint"],
                    "ts": datetime.now().strftime("%H:%M:%S"),
                })

    def broadcast(self, event_type: str, data: object) -> None:
        event = {"type": event_type, "data": data}
        with self._lock:
            for q in self._clients:
                q.put(event)

    # State

    def get_state(self) -> dict:
        current = self._runner.current_step if self._runner else 0
        steps = []
        if self._selected:
            for i, s in enumerate(self._selected.steps):
                cmd = s.command
                content = s.content
                if self._runner:
                    cmd = self._runner.format(cmd) if cmd else None
                    content = self._runner.format(content)
                copyable: dict[str, str] = {}
                if self._runner:
                    for key in s.copyable:
                        val = self._runner.credentials.get(key)
                        if val is not None:
                            copyable[key] = str(val)
                if i < current:
                    hint = self._runner.format(s.hint_done) if self._runner and s.hint_done else s.hint_done
                elif i == current:
                    hint = self._runner.format(s.hint_waiting) if self._runner and s.hint_waiting else s.hint_waiting
                else:
                    hint = ""
                steps.append({
                    "id": s.id,
                    "title": s.title,
                    "content_html": _md_to_html(content),
                    "command": cmd,
                    "copyable": copyable,
                    "hint": hint,
                    "input_prompt": s.input_prompt,
                    "done": i < current,
                    "active": i == current,
                })
        return {
            "tutorials": [
                {
                    "id": t.id,
                    "title": t.title,
                    "category": t.category,
                    "completed": t.id in self._completed,
                }
                for t in self._tutorials
            ],
            "selected": self._selected.id if self._selected else None,
            "runner_state": self._runner.state if self._runner else TutorialState.IDLE,
            "current_step": current,
            "steps": steps,
            "sshmitm_running": self._sshmitm_running,
        }

    # Actions

    def handle_action(self, action: str | None, tutorial_id: str | None) -> None:
        _log.debug("action=%s tutorial_id=%s", action, tutorial_id)
        if action == "select" and tutorial_id:
            tut = next((t for t in self._tutorials if t.id == tutorial_id), None)
            if tut and tut is not self._selected:
                if self._runner:
                    self._runner.stop()
                    self._runner = None
                self._selected = tut
                self.broadcast("state", self.get_state())

        elif action == "start":
            if self._selected and (
                not self._runner or self._runner.state != TutorialState.RUNNING
            ):
                if self._runner:
                    self._runner.stop()
                self._runner = self._make_runner()
                self._runner.start()
                self.broadcast("state", self.get_state())

        elif action == "stop":
            if self._runner:
                self._runner.stop()
                self._runner = None
            self.broadcast("state", self.get_state())

    def submit_input(self, value: str) -> bool:
        if self._runner:
            return self._runner.submit_input(value)
        return False

    def _make_runner(self) -> TutorialRunner:
        assert self._selected is not None
        return TutorialRunner(
            self._selected,
            on_step_complete=self._on_step_complete,
            on_auth_event=self._on_auth_event,
            on_alert=self._on_runner_alert,
            log_socket_path=self._log_socket_path,
        )

    def _on_runner_alert(self, alert: dict) -> None:
        self.broadcast("alert", {"ts": datetime.now().strftime("%H:%M:%S"), **alert})

    def _on_step_complete(self, _idx: int) -> None:
        if (
            self._runner is not None
            and self._runner.state == TutorialState.COMPLETED
            and self._selected is not None
        ):
            mark_completed(self._selected.id)
            self._completed = load_completed()
        self.broadcast("state", self.get_state())

    _AUTH_METHOD_LABELS = {
        "password":             "password",
        "publickey":            "public key",
        "keyboard-interactive": "keyboard-interactive",
        "none":                 "no credentials",
    }

    def _on_auth_event(self, method: str, username: str, ok: bool) -> None:
        # A failed "none" auth is always the standard SSH method-discovery probe,
        # not a real login attempt — every SSH client does this first.
        if method == "none" and not ok:
            return

        method_label = self._AUTH_METHOD_LABELS.get(method, method)
        if method == "none" and ok:
            title = f"{username} logged in without credentials (none auth)"
            detail = "The mock server is configured to accept this username without a password."
        elif ok:
            title = f"{username} authenticated via {method_label}"
            detail = "The mock server accepted the credentials forwarded by SSH-MITM."
        else:
            title = f"{username} failed {method_label} authentication"
            detail = "The mock server rejected the credentials."
        self.broadcast("activity", {
            "source": "mockserver",
            "type": "success" if ok else "warning",
            "title": title,
            "detail": detail,
            "ts": datetime.now().strftime("%H:%M:%S"),
        })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _notify_sshmitm(tutorial_socket_path: str) -> None:
    """Push the tutorial socket path to a running SSH-MITM via its control socket."""
    ctrl = os.path.join(tempfile.gettempdir(), "sshmitm-control.sock")
    if not os.path.exists(ctrl):
        return
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(2.0)
        conn.connect(ctrl)
        conn.sendall(json.dumps({
            "cmd": "attach_tutorial_socket",
            "path": tutorial_socket_path,
        }).encode())
        conn.close()
        _log.debug("notified SSH-MITM of tutorial socket: %s", tutorial_socket_path)
    except OSError:
        pass


def run(tutorials: list[Tutorial], port: int = 0, open_browser: bool = True) -> None:
    # Stay alive when the parent shell exits (e.g. user types 'exit' in a terminal)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

    srv = TutorialWebServer(tutorials, port=port)
    actual_port = srv.server_address[1]
    url = f"http://127.0.0.1:{actual_port}"
    _log.info("Tutorial server listening on %s", url)
    print(f"SSH-MITM Tutorial  →  {url}")
    print(f"Log socket         →  {srv._log_socket_path}")
    _notify_sshmitm(srv._log_socket_path)

    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    if open_browser:
        webbrowser.open(url)

    try:
        thread.join()
    except KeyboardInterrupt:
        srv.shutdown()
