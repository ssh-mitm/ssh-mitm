from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict
from colored.colored import stylize  # type: ignore
from rich._emoji_codes import EMOJI
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
