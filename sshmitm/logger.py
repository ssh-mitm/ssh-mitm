import logging
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Dict

from colored.colored import stylize  # type: ignore[import-untyped]
from pythonjsonlogger import jsonlogger
from rich._emoji_codes import EMOJI
from rich.highlighter import NullHighlighter
from rich.logging import RichHandler

THREAD_DATA = threading.local()


class Colors:
    stylize_func: bool = True

    @classmethod
    def emoji(cls, name: str) -> str:
        if name in EMOJI and cls.stylize_func:
            return EMOJI[name]
        return ""

    @classmethod
    def stylize(cls, text: Any, styles: Any, reset: bool = True) -> Any:
        if not cls.stylize_func:
            return cls.do_noformat(text, styles, reset)
        return cls.do_stylize(text, styles, reset)  # pylint: disable=not-callable

    @classmethod
    def do_stylize(cls, text: Any, styles: Any, reset: bool = True) -> Any:
        return stylize(text, styles, reset)

    @classmethod
    def do_noformat(cls, text: Any, styles: Any, reset: bool = True) -> Any:
        del styles
        del reset
        return text


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


class PlainJsonFormatter(jsonlogger.JsonFormatter):
    def process_log_record(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        log_data["message"] = log_data["message"].strip()
        return log_data

    def add_fields(
        self,
        log_data: Dict[str, Any],
        record: logging.LogRecord,
        message_dict: Dict[str, Any],
    ) -> None:
        super().add_fields(log_data, record, message_dict)
        log_data["tid"] = threading.get_native_id()
        log_data["module"] = record.module

        session = getattr(THREAD_DATA, "session", None)
        log_data["sessionid"] = session.sessionid if session is not None else None

        log_data["timestamp"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
        log_data["level"] = record.levelname
