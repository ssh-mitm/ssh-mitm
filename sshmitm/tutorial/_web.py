"""Simple HTTP server for the SSH-MITM tutorial system."""

from __future__ import annotations

import asyncio
import contextlib
import html as _html
import json
import logging
import pathlib
import re
import signal
import subprocess
import webbrowser
from datetime import datetime
from importlib import resources as _resources
from typing import TYPE_CHECKING

from aiohttp import web

from sshmitm.tutorial._definitions import Tutorial
from sshmitm.tutorial._conditions import has_continue
from sshmitm.tutorial._progress import load_completed, mark_completed
from sshmitm.tutorial._runner import TutorialRunner, TutorialState

if TYPE_CHECKING:
    pass

_log = logging.getLogger(__name__)
_LOGO_PATH = pathlib.Path(__file__).parent.parent / "data" / "ssh-mitm-logo.png"
_STATIC = _resources.files("sshmitm.tutorial.static")

_STATIC_TYPES: dict[str, tuple[str, str]] = {
    "tutorial.html": ("text/html", "utf-8"),
    "tutorial.css":  ("text/css", "utf-8"),
    "tutorial.js":   ("application/javascript", "utf-8"),
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
# Server
# ---------------------------------------------------------------------------

class TutorialWebServer:

    def __init__(self, tutorials: list[Tutorial]) -> None:
        self._tutorials = tutorials
        self._selected: Tutorial | None = None
        self._runner: TutorialRunner | None = None
        self._completed: set[str] = load_completed()
        self._clients: list[asyncio.Queue[dict]] = []
        self._lock = asyncio.Lock()
        self._sshmitm_running = False
        self._loop: asyncio.AbstractEventLoop | None = None

    # SSE client management

    async def _add_client(self, q: asyncio.Queue[dict]) -> None:
        async with self._lock:
            self._clients.append(q)

    async def _remove_client(self, q: asyncio.Queue[dict]) -> None:
        async with self._lock:
            with contextlib.suppress(ValueError):
                self._clients.remove(q)

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

    async def _status_check_loop(self) -> None:
        while True:
            await asyncio.sleep(2)
            async with self._lock:
                tut = self._selected
                prev = self._sshmitm_running
            if tut is None:
                continue
            running = self._port_open(tut.sshmitm_port)
            async with self._lock:
                self._sshmitm_running = running
            if running != prev:
                await self.broadcast("state", self.get_state())

    async def broadcast(self, event_type: str, data: object) -> None:
        event = {"type": event_type, "data": data}
        async with self._lock:
            for q in self._clients:
                await q.put(event)

    def _broadcast_threadsafe(self, event_type: str, data: object) -> None:
        """Bridge from TutorialRunner threads into the asyncio event loop."""
        assert self._loop is not None
        asyncio.run_coroutine_threadsafe(self.broadcast(event_type, data), self._loop)

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
                        val = self._runner.tutorial_session_data.get(key)
                        if val is not None:
                            copyable[key] = str(val)
                if self._runner:
                    hint, hint_type = self._runner.get_step_hint(i)
                else:
                    hint, hint_type = (s.hint_done if i < current else s.hint_waiting if i == current else ""), "info"
                steps.append({
                    "id": s.id,
                    "title": s.title,
                    "content_html": _md_to_html(content),
                    "command": cmd,
                    "copyable": copyable,
                    "hint": hint,
                    "hint_type": hint_type,
                    "done": i < current,
                    "active": self._runner is not None and i == current,
                    "has_continue": has_continue(s.condition),
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
            "user_inputs": self._runner.get_active_user_inputs() if self._runner else [],
            "step_ready": self._runner.is_step_ready() if self._runner else False,
        }

    # Actions

    async def handle_action(self, action: str | None, tutorial_id: str | None) -> None:
        _log.debug("action=%s tutorial_id=%s", action, tutorial_id)
        if action == "select" and tutorial_id:
            tut = next((t for t in self._tutorials if t.id == tutorial_id), None)
            if tut and tut is not self._selected:
                if self._runner:
                    self._runner.stop()
                    self._runner = None
                self._selected = tut
                await self.broadcast("state", self.get_state())

        elif action == "start":
            if self._selected and (
                not self._runner or self._runner.state != TutorialState.RUNNING
            ):
                if self._runner:
                    self._runner.stop()
                self._runner = self._make_runner()
                self._runner.start()
                await self.broadcast("state", self.get_state())

        elif action == "stop":
            if self._runner:
                self._runner.stop()
                self._runner = None
            await self.broadcast("state", self.get_state())

    async def submit_all(self, values: dict[str, str]) -> dict[str, bool]:
        if not self._runner:
            return {}
        results = {key: self._runner.submit_input(key, value) for key, value in values.items()}
        await self.broadcast("state", self.get_state())
        return results

    async def advance(self) -> bool:
        if self._runner:
            advanced = self._runner.advance()
            if advanced:
                await self.broadcast("state", self.get_state())
            return advanced
        return False

    def _make_runner(self) -> TutorialRunner:
        assert self._selected is not None
        return TutorialRunner(
            self._selected,
            on_step_complete=self._on_step_complete,
            on_auth_event=self._on_auth_event,
            on_alert=self._on_runner_alert,
            on_state_update=lambda: self._broadcast_threadsafe("state", self.get_state()),
        )

    def _on_runner_alert(self, alert: dict) -> None:
        self._broadcast_threadsafe("alert", {"ts": datetime.now().strftime("%H:%M:%S"), **alert})

    def _on_step_complete(self, _idx: int) -> None:
        if (
            self._runner is not None
            and self._runner.state == TutorialState.COMPLETED
            and self._selected is not None
        ):
            mark_completed(self._selected.id)
            self._completed = load_completed()
        self._broadcast_threadsafe("state", self.get_state())

    _AUTH_METHOD_LABELS = {
        "password":             "password",
        "publickey":            "public key",
        "keyboard-interactive": "keyboard-interactive",
        "none":                 "no credentials",
    }

    def _on_auth_event(self, method: str, username: str, ok: bool) -> None:
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
        self._broadcast_threadsafe("activity", {
            "source": "mockserver",
            "type": "success" if ok else "warning",
            "title": title,
            "detail": detail,
            "ts": datetime.now().strftime("%H:%M:%S"),
        })

    # HTTP route handlers

    async def _handle_root(self, _request: web.Request) -> web.Response:
        return web.Response(body=_read_static("tutorial.html"),
                            content_type="text/html", charset="utf-8")

    async def _handle_state(self, _request: web.Request) -> web.Response:
        return web.json_response(self.get_state())

    async def _handle_events(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse()
        response.headers["Content-Type"] = "text/event-stream"
        response.headers["Cache-Control"] = "no-cache"
        response.headers["X-Accel-Buffering"] = "no"
        await response.prepare(request)

        q: asyncio.Queue[dict] = asyncio.Queue()
        await self._add_client(q)
        try:
            await self._sse_write(response, {"type": "state", "data": self.get_state()})
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    await response.write(b": keepalive\n\n")
                    continue
                await self._sse_write(response, event)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            await self._remove_client(q)
        return response

    async def _handle_logo(self, _request: web.Request) -> web.Response:
        if _LOGO_PATH.exists():
            return web.Response(body=_LOGO_PATH.read_bytes(), content_type="image/png")
        return web.Response(status=404)

    async def _handle_static(self, request: web.Request) -> web.Response:
        name = request.match_info["name"]
        if name in _STATIC_TYPES:
            ct, charset = _STATIC_TYPES[name]
            return web.Response(body=_read_static(name), content_type=ct, charset=charset)
        return web.Response(status=404)

    async def _handle_action(self, request: web.Request) -> web.Response:
        body = await request.json()
        action = body.get("action")
        if action == "submit_all":
            results = await self.submit_all(body.get("values", {}))
            return web.json_response({"ok": True, "results": results})
        if action == "advance":
            ok = await self.advance()
            return web.json_response({"ok": True, "advanced": ok})
        await self.handle_action(action, body.get("tutorial_id"))
        return web.json_response({"ok": True})

    @staticmethod
    async def _sse_write(response: web.StreamResponse, event: dict) -> None:
        await response.write(f"data: {json.dumps(event)}\n\n".encode())

    def build_app(self) -> web.Application:
        app = web.Application()

        async def on_startup(_app: web.Application) -> None:
            self._loop = asyncio.get_running_loop()
            _app["status_task"] = asyncio.create_task(self._status_check_loop())

        async def on_cleanup(_app: web.Application) -> None:
            task: asyncio.Task = _app.get("status_task")
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        app.on_startup.append(on_startup)
        app.on_cleanup.append(on_cleanup)
        app.router.add_get("/", self._handle_root)
        app.router.add_get("/state", self._handle_state)
        app.router.add_get("/events", self._handle_events)
        app.router.add_get("/logo.png", self._handle_logo)
        app.router.add_get("/static/{name}", self._handle_static)
        app.router.add_post("/action", self._handle_action)
        return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _load_tutorials() -> list[Tutorial]:
    from importlib.metadata import entry_points
    tutorials: list[Tutorial] = []
    for ep in entry_points(group="sshmitm.Tutorial"):
        try:
            cls = ep.load()
        except Exception:
            _log.warning("Failed to load tutorial entry point %r", ep.name, exc_info=True)
            continue
        if isinstance(cls, type) and issubclass(cls, Tutorial):
            tutorials.append(cls())
    return sorted(tutorials, key=lambda t: t.id)


async def _run_async(port: int, open_browser: bool) -> None:
    srv = TutorialWebServer(_load_tutorials())
    app = srv.build_app()

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()

    # resolve actual port when port=0 was requested
    actual_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    url = f"http://127.0.0.1:{actual_port}"
    _log.info("Tutorial server listening on %s", url)
    print(f"SSH-MITM Tutorial  →  {url}")

    if open_browser:
        try:
            subprocess.Popen(
                ["xdg-open", url],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            webbrowser.open(url)

    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()


def run(port: int = 0, open_browser: bool = True) -> None:
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        asyncio.run(_run_async(port, open_browser))
    except KeyboardInterrupt:
        pass
