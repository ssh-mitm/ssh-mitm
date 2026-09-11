import base64
import dataclasses
import datetime
import enum
import json
import logging
import sys
import threading
import traceback
from types import TracebackType
from typing import Any

from rich.highlighter import NullHighlighter
from rich.logging import RichHandler

from sshmitm.moduleparser.colors import Colors

THREAD_DATA = threading.local()

# LogRecord attributes that are always present and must not be re-emitted as
# top-level JSON fields by the generic extra-field merge below; "message" and
# "module" are handled explicitly instead. Mirrors python-json-logger's
# RESERVED_ATTRS (see pythonjsonlogger.core), minus the fields ssh-mitm never
# populates (taskName requires Python 3.12+, harmless to always exclude).
_RESERVED_LOG_RECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class _JsonEncoder(json.JSONEncoder):
    """Renders values that ``json.dumps`` can't handle natively.

    Only exercised by fields passed through ``logging.*(..., extra={...})``;
    covers every type ssh-mitm's own logging calls can produce.
    """

    def default(self, o: Any) -> Any:
        if isinstance(o, datetime.datetime | datetime.date | datetime.time):
            return o.isoformat()
        if isinstance(o, BaseException):
            return f"{o.__class__.__name__}: {o}"
        if isinstance(o, TracebackType):
            return "".join(traceback.format_tb(o)).strip()
        if isinstance(o, enum.Enum):
            return o.value
        if isinstance(o, bytes | bytearray):
            return base64.urlsafe_b64encode(o).decode("ascii")
        if dataclasses.is_dataclass(o) and not isinstance(o, type):
            return dataclasses.asdict(o)
        if isinstance(o, type):
            return o.__name__
        try:
            return str(o)
        except Exception:  # noqa: BLE001 # pylint: disable=broad-exception-caught
            return "__could_not_encode__"


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


class PlainJsonFormatter(logging.Formatter):
    """Renders each log record as a single JSON object.

    A minimal, ssh-mitm-specific stand-in for python-json-logger's
    JsonFormatter - only the behavior ssh-mitm's own logging calls actually
    rely on (message, exception formatting, extra={...} field merging, JSON
    encoding of non-native types) is reimplemented here, to avoid pulling in
    a whole extra dependency for it.
    """

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage().strip()

        log_data: dict[str, Any] = {"message": record.message}

        if record.exc_info:
            log_data["exc_info"] = self.formatException(record.exc_info)
        elif record.exc_text:
            log_data["exc_info"] = record.exc_text
        if record.stack_info:
            log_data["stack_info"] = self.formatStack(record.stack_info)

        log_data.update(
            {
                key: value
                for key, value in record.__dict__.items()
                if key not in _RESERVED_LOG_RECORD_ATTRS and not key.startswith("_")
            }
        )

        self.add_fields(log_data, record)

        return json.dumps(log_data, cls=_JsonEncoder)

    def add_fields(self, log_data: dict[str, Any], record: logging.LogRecord) -> None:
        log_data["tid"] = threading.get_native_id()
        log_data["module"] = record.module

        session = getattr(THREAD_DATA, "session", None)
        log_data["sessionid"] = session.sessionid if session is not None else None

        log_data["timestamp"] = datetime.datetime.now(datetime.UTC).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        log_data["level"] = record.levelname
