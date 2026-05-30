import logging
import os
import socket
import sys
import threading
from datetime import UTC, datetime
from typing import Any

from pythonjsonlogger.json import JsonFormatter
from rich.highlighter import NullHighlighter
from rich.logging import RichHandler

from sshmitm.moduleparser.colors import Colors

THREAD_DATA = threading.local()


class FailSaveLogStream:
    def __init__(self, debug: bool = False) -> None:
        self.debug = debug

    def write(self, text: str) -> None:
        sys.stdout.write(text)

    def flush(self) -> None:
        try:
            sys.stdout.flush()
        except BrokenPipeError:
            sys.stdout = sys.stderr
            self.activate_format(debug=self.debug)
            logging.error("unable to pipe output to logviewer!")

    @classmethod
    def activate_format(cls, *, debug: bool = False) -> None:
        Colors.stylize_func = True
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.addHandler(
            RichHandler(
                highlighter=NullHighlighter(),
                markup=False,
                rich_tracebacks=True,
                enable_link_path=debug,
                show_path=debug,
            )
        )


class PlainJsonFormatter(JsonFormatter):
    def process_log_record(self, log_data: dict[str, Any]) -> dict[str, Any]:
        log_data["message"] = log_data["message"].strip()
        return log_data

    def add_fields(
        self,
        log_data: dict[str, Any],
        record: logging.LogRecord,
        message_dict: dict[str, Any],
    ) -> None:
        super().add_fields(log_data, record, message_dict)
        log_data["tid"] = threading.get_native_id()
        log_data["module"] = record.module

        session = getattr(THREAD_DATA, "session", None)
        log_data["sessionid"] = session.sessionid if session is not None else None

        log_data["timestamp"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        log_data["level"] = record.levelname


class TutorialSocketHandler(logging.Handler):
    """Forwards log records as newline-delimited JSON to a Unix domain socket.

    Connection errors during emit are silently ignored so SSH-MITM never
    blocks or crashes when the tutorial server disappears mid-session.
    """

    def __init__(self, path: str) -> None:
        super().__init__()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        self._sock = sock
        self.setFormatter(PlainJsonFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record) + "\n"
            self._sock.sendall(msg.encode())
        except OSError:
            pass


import json as _json
import tempfile as _tempfile

_DEFAULT_TUTORIAL_SOCKET = os.path.join(
    _tempfile.gettempdir(), "sshmitm-tutorial.sock"
)
_CONTROL_SOCKET_PATH = os.path.join(
    _tempfile.gettempdir(), "sshmitm-control.sock"
)


def _detach_tutorial_handlers() -> None:
    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if not isinstance(h, TutorialSocketHandler)]


def attach_tutorial_handler(path: str | None = None) -> None:
    """Connect to the tutorial log socket if it exists.

    Called at SSH-MITM startup (pull) and by the control socket listener
    when the tutorial server pushes a new socket path (push).
    """
    if path is None:
        path = os.environ.get("SSHMITM_TUTORIAL_SOCKET") or _DEFAULT_TUTORIAL_SOCKET
    if not os.path.exists(path):
        return
    try:
        _detach_tutorial_handlers()
        logging.getLogger().addHandler(TutorialSocketHandler(path))
        logging.debug("tutorial log socket attached: %s", path)
    except OSError as exc:
        logging.debug("could not connect to tutorial socket %s: %s", path, exc)


def start_control_socket() -> None:
    """Open a control socket so the tutorial server can push its socket path.

    Listens on _CONTROL_SOCKET_PATH for single-line JSON commands:
      {"cmd": "attach_tutorial_socket", "path": "/tmp/sshmitm-tutorial.sock"}

    Blocks until the socket is ready so callers know it exists.
    """
    ctrl = _CONTROL_SOCKET_PATH
    if os.path.exists(ctrl):
        try:
            os.unlink(ctrl)
        except OSError:
            pass

    ready = threading.Event()

    def _serve() -> None:
        try:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(ctrl)
            srv.listen(5)
            srv.settimeout(1.0)
            ready.set()
            while True:
                try:
                    conn, _ = srv.accept()
                    try:
                        data = conn.recv(4096)
                        msg = _json.loads(data)
                        if msg.get("cmd") == "attach_tutorial_socket":
                            attach_tutorial_handler(msg["path"])
                            logging.debug("tutorial handler attached via push: %s", msg["path"])
                    except Exception:  # noqa: BLE001
                        pass
                    finally:
                        conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except OSError:
            pass
        finally:
            ready.set()

    threading.Thread(target=_serve, daemon=True).start()
    ready.wait(timeout=2.0)
