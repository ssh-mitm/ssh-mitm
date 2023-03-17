from datetime import datetime, timezone
import logging
import sys
import threading
from typing import Any, Dict
from colored.colored import stylize  # type: ignore
from rich._emoji_codes import EMOJI
from rich.logging import RichHandler
from rich.highlighter import NullHighlighter
from pythonjsonlogger import jsonlogger


THREAD_DATA = threading.local()


class Colors:

    stylize_func: bool = True

    @classmethod
    def emoji(cls, name: str) -> str:
        if name in EMOJI and cls.stylize_func:
            return EMOJI[name]
        return ''

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


class FailSaveLogStream():

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug

    def write(self, text: str) -> None:
        sys.stdout.write(text)

    def flush(self) -> None:
        try:
            sys.stdout.flush()
        except BrokenPipeError:
            sys.stdout = sys.stderr
            self.activate_format()
            logging.error("unable to pipe output to logviewer!")

    def activate_format(self) -> None:
        Colors.stylize_func = True
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.addHandler(RichHandler(
            highlighter=NullHighlighter(),
            markup=False,
            rich_tracebacks=True,
            enable_link_path=self.debug,
            show_path=self.debug
        ))


class PlainJsonFormatter(jsonlogger.JsonFormatter):

    def process_log_record(self, log_record: Dict[str, Any]) -> Dict[str, Any]:
        log_record['message'] = log_record['message'].strip()
        return log_record

    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        super().add_fields(log_record, record, message_dict)
        log_record['tid'] = threading.get_native_id()
        log_record['module'] = record.module

        session = getattr(THREAD_DATA, 'session', None)
        log_record['sessionid'] = session.sessionid if session is not None else None

        log_record['timestamp'] = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        log_record['level'] = record.levelname
