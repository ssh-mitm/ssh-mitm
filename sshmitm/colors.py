import os
import sys

from rich.emoji import Emoji, NoEmoji

_ESC = "\x1b["
_RESET = f"{_ESC}0m"
_BOLD = f"{_ESC}1m"

# 8-bit ANSI foreground color codes, matching the standard/bright 16-color
# palette indices any terminal supports.
_FG = {
    "red": f"{_ESC}38;5;1m",
    "green": f"{_ESC}38;5;2m",
    "yellow": f"{_ESC}38;5;3m",
    "blue": f"{_ESC}38;5;4m",
    "light_gray": f"{_ESC}38;5;7m",
    "dark_gray": f"{_ESC}38;5;8m",
    "light_blue": f"{_ESC}38;5;12m",
}


def _supports_color() -> bool:
    """Baseline "is coloring even possible here" check: the de facto
    FORCE_COLOR/NO_COLOR conventions (https://no-color.org) plus a plain
    TTY check.

    This runs independently of Colors.stylize_func, which is an explicit
    override some callers set (e.g. JSON logging, the Textual plugin
    browser) - not every code path that renders text runs through
    whatever sets that flag. argparse's own --help handling, in
    particular, exits before sshmitm.cli.main() ever gets a chance to set
    it, so ModuleFormatter's use of Colors.error() below would otherwise
    always emit color, even when --help is piped to a file.
    """
    force_color = os.environ.get("FORCE_COLOR")
    if force_color is not None:
        return force_color != "0"
    if "NO_COLOR" in os.environ:
        return False
    return sys.stdout.isatty()


class Colors:
    stylize_func: bool = True

    @classmethod
    def emoji(cls, name: str) -> str:
        if not cls.stylize_func:
            return ""
        try:
            return str(Emoji(name))
        except NoEmoji:
            return ""

    @classmethod
    def stylize(
        cls, text: object, color: str | None = None, *, bold: bool = False
    ) -> str:
        if not cls.stylize_func or not _supports_color():
            return str(text)
        formatting = (_FG[color] if color else "") + (_BOLD if bold else "")
        return f"{formatting}{text}{_RESET}"

    @classmethod
    def error(cls, text: object, *, bold: bool = True) -> str:
        return cls.stylize(text, "red", bold=bold)

    @classmethod
    def warning(cls, text: object, *, bold: bool = True) -> str:
        return cls.stylize(text, "yellow", bold=bold)

    @classmethod
    def success(cls, text: object, *, bold: bool = True) -> str:
        return cls.stylize(text, "green", bold=bold)

    @classmethod
    def heading(cls, text: object) -> str:
        return cls.stylize(text, "blue", bold=True)

    @classmethod
    def highlight(cls, text: object, *, bold: bool = True) -> str:
        return cls.stylize(text, "light_blue", bold=bold)

    @classmethod
    def muted(cls, text: object) -> str:
        return cls.stylize(text, "dark_gray")

    @classmethod
    def dimmed(cls, text: object) -> str:
        return cls.stylize(text, "light_gray", bold=True)
