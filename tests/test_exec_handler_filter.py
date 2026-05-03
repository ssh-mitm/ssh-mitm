"""Tests for SCPBaseForwarder.is_handler_allowed() filter logic."""

import warnings

import pytest

from sshmitm.forwarders.scp import SCPBaseForwarder

_allow = SCPBaseForwarder.is_handler_allowed  # noqa: SLF001


@pytest.mark.parametrize(
    "name, enabled, disabled, expected",
    [
        # --- default behaviour ---
        ("scp",  ["ALL"],  ["NONE"], True),
        ("mosh", ["ALL"],  ["NONE"], True),
        # --- enabled=ALL, specific disabled (blacklist) ---
        ("scp",  ["ALL"],  ["scp"],        False),
        ("mosh", ["ALL"],  ["scp"],        True),
        ("scp",  ["ALL"],  ["scp", "mosh"], False),
        ("mosh", ["ALL"],  ["scp", "mosh"], False),
        # --- specific enabled, disabled=NONE (whitelist) ---
        ("scp",  ["scp"],        ["NONE"], True),
        ("mosh", ["scp"],        ["NONE"], False),
        ("scp",  ["scp", "mosh"], ["NONE"], True),
        ("mosh", ["scp", "mosh"], ["NONE"], True),
        # --- disabled=ALL, specific enabled overrides (default-deny) ---
        ("scp",  ["scp"],  ["ALL"], True),
        ("mosh", ["scp"],  ["ALL"], False),
        ("mosh", ["mosh"], ["ALL"], True),
        ("scp",  ["mosh"], ["ALL"], False),
        # --- both NONE: nothing runs ---
        ("scp",  ["NONE"], ["NONE"], False),
        ("mosh", ["NONE"], ["NONE"], False),
        # --- enabled=NONE dominates regardless of disabled ---
        ("scp",  ["NONE"], ["ALL"],  False),
        ("scp",  ["NONE"], ["scp"],  False),
        # --- both specific lists: disabled wins on overlap ---
        ("scp",  ["scp", "mosh"], ["scp"],        False),  # scp in both -> disabled wins
        ("mosh", ["scp", "mosh"], ["scp"],        True),   # mosh only in enabled -> runs
        ("scp",  ["scp", "mosh"], ["scp", "mosh"], False),
        ("mosh", ["scp", "mosh"], ["scp", "mosh"], False),
        # --- handler not in either list ---
        ("netconf", ["scp"],  ["NONE"], False),
        ("netconf", ["ALL"],  ["scp"],  True),
        ("netconf", ["NONE"], ["NONE"], False),
    ],
)
def test_is_handler_allowed(
    name: str, enabled: list[str], disabled: list[str], expected: bool
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert _allow(name, enabled, disabled) == expected


def test_all_all_returns_false_with_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = _allow("scp", ["ALL"], ["ALL"])

    assert result is False
    assert any("no handlers will run" in str(w.message) for w in caught)
