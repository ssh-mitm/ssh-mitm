"""Tests for sshmitm.colors."""

import uuid
from collections.abc import Generator

import pytest

from sshmitm.colors import Colors

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_RED = "\x1b[38;5;1m"
_LIGHT_BLUE = "\x1b[38;5;12m"


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch: pytest.MonkeyPatch) -> Generator[None]:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    # pytest captures stdout, so sys.stdout.isatty() is always False here;
    # force a color-capable terminal as the default for these tests, and
    # override it explicitly wherever the TTY check itself is the point.
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    Colors.stylize_func = True
    yield
    Colors.stylize_func = True


def test_stylize_applies_color_and_reset() -> None:
    assert Colors.stylize("hi", "red") == f"{_RED}hi{_RESET}"


def test_stylize_applies_bold() -> None:
    assert Colors.stylize("hi", "red", bold=True) == f"{_RED}{_BOLD}hi{_RESET}"


def test_stylize_without_color_still_supports_bold_only() -> None:
    assert Colors.stylize("hi", bold=True) == f"{_BOLD}hi{_RESET}"


def test_stylize_accepts_non_str_input() -> None:
    session_id = uuid.uuid4()
    assert Colors.stylize(session_id, "light_blue") == f"{_LIGHT_BLUE}{session_id}{_RESET}"


def test_stylize_func_false_disables_styling() -> None:
    Colors.stylize_func = False
    assert Colors.stylize("hi", "red", bold=True) == "hi"


def test_stylize_func_false_stringifies_non_str_input() -> None:
    Colors.stylize_func = False
    session_id = uuid.uuid4()
    assert Colors.stylize(session_id, "red") == str(session_id)


def test_no_color_env_disables_styling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert Colors.stylize("hi", "red") == "hi"


def test_force_color_zero_disables_styling(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "0")
    assert Colors.stylize("hi", "red") == "hi"


def test_force_color_nonzero_keeps_styling_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert Colors.stylize("hi", "red") == f"{_RED}hi{_RESET}"


def test_force_color_does_not_override_stylize_func_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    Colors.stylize_func = False
    assert Colors.stylize("hi", "red") == "hi"


def test_non_tty_disables_styling(monkeypatch: pytest.MonkeyPatch) -> None:
    # e.g. argparse's own --help handling, which never runs through
    # whatever sets Colors.stylize_func - the baseline TTY check must
    # still apply.
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    assert Colors.stylize("hi", "red") == "hi"


def test_force_color_enables_styling_even_when_not_a_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert Colors.stylize("hi", "red") == f"{_RED}hi{_RESET}"


@pytest.mark.parametrize(
    ("method_name", "color", "default_bold"),
    [
        ("error", "red", True),
        ("warning", "yellow", True),
        ("success", "green", True),
        ("highlight", "light_blue", True),
        ("muted", "dark_gray", False),
        ("dimmed", "light_gray", True),
    ],
)
def test_semantic_methods_match_stylize(
    method_name: str, color: str, default_bold: bool
) -> None:
    method = getattr(Colors, method_name)
    assert method("hi") == Colors.stylize("hi", color, bold=default_bold)


def test_heading_is_always_bold_blue() -> None:
    assert Colors.heading("hi") == Colors.stylize("hi", "blue", bold=True)


def test_error_warning_success_accept_bold_false() -> None:
    assert Colors.error("hi", bold=False) == Colors.stylize("hi", "red", bold=False)
    assert Colors.warning("hi", bold=False) == Colors.stylize("hi", "yellow", bold=False)
    assert Colors.success("hi", bold=False) == Colors.stylize("hi", "green", bold=False)


def test_emoji_returns_glyph_for_known_name() -> None:
    assert Colors.emoji("information") != ""


def test_emoji_returns_empty_for_unknown_name() -> None:
    assert Colors.emoji("this-emoji-does-not-exist") == ""


def test_emoji_returns_empty_when_stylize_func_false() -> None:
    Colors.stylize_func = False
    assert Colors.emoji("information") == ""
