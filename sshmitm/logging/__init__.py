from typing import Union
from colored.colored import stylize, attr, fg  # type: ignore
from rich._emoji_codes import EMOJI
from pythonjsonlogger import jsonlogger


class Colors:

    stylize_func = None

    @classmethod
    def emoji(cls, name: str) -> str:
        if name in EMOJI and cls.stylize_func and cls.stylize_func is not None:
            return EMOJI[name]
        return ''

    @classmethod
    def stylize(cls, text: Union[str, bytes], styles, reset=True):
        if cls.stylize_func is None:
            return cls.do_noformat(text, styles, reset)
        return cls.stylize_func(text, styles, reset)

    @classmethod
    def do_stylize(cls, text: Union[str, bytes], styles, reset=True):
        return stylize(text, styles, reset)

    @classmethod
    def do_noformat(cls, text: Union[str, bytes], styles, reset=True):
        del styles
        del reset
        return text


class PlainJsonFormatter(jsonlogger.JsonFormatter):

    def process_log_record(self, log_record):
        log_record['message'] = log_record['message'].strip()
        return log_record