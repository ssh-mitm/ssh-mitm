"""Plugin metadata data structures and argparse helpers."""

from __future__ import annotations

import argparse
import inspect
import re
from dataclasses import dataclass

from sshmitm.moduleparser.modules import BaseModule

_SKIP_GROUPS: frozenset[str | None] = frozenset(
    {
        "positional arguments",
        "optional arguments",
        "options",
        "Available commands",
        None,
    }
)


def class_to_label(cls_name: str) -> str:
    """Derive a human-readable label from a base-class name."""
    name = cls_name.replace("Base", "")
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|\b)|[A-Z][a-z]+|\d+", name)
    return " ".join(words)


def extract_groups(
    parser: argparse.ArgumentParser,
    skip: frozenset[str | None] | set[str | None] = _SKIP_GROUPS,
) -> list[GeneralGroupInfo]:
    """Return visible argument groups from *parser*, excluding *skip* titles."""
    groups: list[GeneralGroupInfo] = []
    for g in parser._action_groups:  # pylint: disable=protected-access
        if g.title in skip:
            continue
        visible = [
            a
            for a in g._group_actions  # pylint: disable=protected-access
            if a.dest is not argparse.SUPPRESS
        ]
        if not visible:
            continue
        add_arg = getattr(g, "add_argument", None)
        cfg_section = (
            getattr(add_arg, "config_section", None) or ""
            if add_arg is not None
            else ""
        )
        groups.append(
            GeneralGroupInfo(
                title=g.title or "(unnamed)",
                description=g.description or "",
                config_section=cfg_section,
                group=g,
            )
        )
    return groups


def visible_actions(group: argparse._ArgumentGroup) -> list[argparse.Action]:
    return [
        a
        for a in group._group_actions  # pylint: disable=protected-access
        if a.dest is not argparse.SUPPRESS
    ]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class PluginTypeInfo:
    type_label: str
    cli_flag: str
    config_key: str
    help_text: str
    base_class: type[BaseModule]

    @property
    def doc(self) -> str:
        return inspect.cleandoc(self.base_class.__doc__ or "")


@dataclass
class GeneralGroupInfo:
    title: str
    description: str
    config_section: str
    group: argparse._ArgumentGroup


@dataclass
class GeneralActionInfo:
    action: argparse.Action
    group: argparse._ArgumentGroup
    group_title: str
    config_section: str


@dataclass
class ExecHandlerInfo:
    name: str
    ep_value: str
    command_prefix: bytes
    loaded_class: type
    enabled: bool

    @property
    def type_label(self) -> str:
        return "Exec Handler"

    @property
    def doc(self) -> str:
        return inspect.cleandoc(self.loaded_class.__doc__ or "")

    @property
    def config_section(self) -> str:
        return f"{self.loaded_class.__module__}:{self.loaded_class.__name__}"

    @property
    def argument_groups(self) -> list[argparse._ArgumentGroup]:
        try:
            if not issubclass(self.loaded_class, BaseModule):
                return []
            parser = self.loaded_class.parser()
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            return []
        return [
            g
            for g in parser._action_groups  # pylint: disable=protected-access
            if g.title not in _SKIP_GROUPS
            and any(
                a.dest is not argparse.SUPPRESS and a.help != argparse.SUPPRESS
                for a in g._group_actions  # pylint: disable=protected-access
            )
        ]

    @property
    def actions(self) -> list[argparse.Action]:
        return [
            a
            for g in self.argument_groups
            for a in g._group_actions  # pylint: disable=protected-access
            if a.dest is not argparse.SUPPRESS and a.help != argparse.SUPPRESS
        ]


@dataclass
class PluginInfo:
    name: str
    ep_value: str
    type_label: str
    cli_flag: str
    base_class: type[BaseModule]
    loaded_class: type[BaseModule]

    @property
    def config_section(self) -> str:
        return f"{self.loaded_class.__module__}:{self.loaded_class.__name__}"

    @property
    def doc(self) -> str:
        return inspect.cleandoc(self.loaded_class.__doc__ or "")

    @property
    def argument_groups(self) -> list[argparse._ArgumentGroup]:
        try:
            parser = self.loaded_class.parser()
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            return []
        return [
            g
            for g in parser._action_groups  # pylint: disable=protected-access
            if g.title not in _SKIP_GROUPS
            and any(
                a.dest is not argparse.SUPPRESS and a.help != argparse.SUPPRESS
                for a in g._group_actions  # pylint: disable=protected-access
            )
        ]

    @property
    def actions(self) -> list[argparse.Action]:
        return [
            a
            for g in self.argument_groups
            for a in g._group_actions  # pylint: disable=protected-access
            if a.dest is not argparse.SUPPRESS and a.help != argparse.SUPPRESS
        ]
