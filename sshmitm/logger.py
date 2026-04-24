import logging
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
