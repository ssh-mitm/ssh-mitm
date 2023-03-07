from datetime import datetime, timezone
import threading
from typing import Callable, Any, Optional
from colored.colored import stylize  # type: ignore
from rich._emoji_codes import EMOJI
from pythonjsonlogger import jsonlogger


THREAD_DATA = threading.local()


class Colors:

    stylize_func: Optional[Callable[[Any, Any, bool], Any]] = None

    @classmethod
    def emoji(cls, name: str) -> str:
        if name in EMOJI and cls.stylize_func and cls.stylize_func is not None:
            return EMOJI[name]
        return ''

    @classmethod
    def stylize(cls, text: Any, styles: Any, reset: bool = True) -> Any:
        if cls.stylize_func is None:
            return cls.do_noformat(text, styles, reset)
        return cls.stylize_func(text, styles, reset)  # pylint: disable=not-callable

    @classmethod
    def do_stylize(cls, text: Any, styles: Any, reset: bool = True) -> Any:
        return stylize(text, styles, reset)

    @classmethod
    def do_noformat(cls, text: Any, styles: Any, reset: bool = True) -> Any:
        del styles
        del reset
        return text


class PlainJsonFormatter(jsonlogger.JsonFormatter):

    def process_log_record(self, log_record: Any) -> Any:
        log_record['message'] = log_record['message'].strip()
        return log_record

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record['tid'] = threading.get_native_id()

        session = getattr(THREAD_DATA, 'session', None)
        log_record['sessionid'] = session.sessionid if session is not None else None

        if not log_record.get('timestamp'):
            # this doesn't use record.created, so it is slightly off
            now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            log_record['timestamp'] = now
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname
