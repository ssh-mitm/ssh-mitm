from typing import Any

from colored.colored import stylize as _stylize
from rich._emoji_codes import EMOJI


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
        return cls.do_stylize(text, styles, reset)

    @classmethod
    def do_stylize(cls, text: Any, styles: Any, reset: bool = True) -> Any:
        return _stylize(text, styles, reset)

    @classmethod
    def do_noformat(cls, text: Any, styles: Any, reset: bool = True) -> Any:
        del styles
        del reset
        return text
