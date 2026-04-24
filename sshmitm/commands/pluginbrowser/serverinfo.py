"""Cached discovery of SSH-MITM server plugin types and argument groups."""

from __future__ import annotations

import argparse
from functools import cached_property
from typing import Any

from sshmitm.cli import create_parser as _create_main_parser
from sshmitm.moduleparser.parser import ModuleParser
from sshmitm.moduleparser.plugininfo import (
    GeneralGroupInfo,
    PluginTypeInfo,
    class_to_label,
    extract_groups,
)
from sshmitm.server.cli import SSHServerModules
from sshmitm.utils import metadata

_STANDARD_GROUPS: set[str | None] = {
    "positional arguments",
    "optional arguments",
    "options",
    None,
}


class ServerInfo:
    """Lazy, cached discovery of all plugin types and general argument groups.

    Use the module-level singleton ``server_info`` rather than instantiating directly.
    """

    @cached_property
    def _data(self) -> tuple[list[PluginTypeInfo], list[GeneralGroupInfo]]:
        main_parser = _create_main_parser()
        general_groups = extract_groups(main_parser, _STANDARD_GROUPS)

        mp = ModuleParser(prog="sshmitm")
        sub = mp.add_subparsers()
        cmd = SSHServerModules("server", sub)
        cmd.register_arguments()

        plugin_types = [
            PluginTypeInfo(
                type_label=class_to_label(baseclass.__name__),
                cli_flag=action.option_strings[0],
                help_text=(
                    ""
                    if not action.help or action.help == argparse.SUPPRESS
                    else action.help
                ),
                base_class=baseclass,
            )
            for action, baseclass in cmd.parser._extra_modules  # pylint: disable=protected-access
            if action.option_strings
        ]

        general_groups += extract_groups(cmd.parser, _STANDARD_GROUPS)
        return plugin_types, general_groups

    @property
    def plugin_types(self) -> list[PluginTypeInfo]:
        return self._data[0]

    @property
    def general_groups(self) -> list[GeneralGroupInfo]:
        return self._data[1]

    @cached_property
    def ep_value_to_name(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for type_info in self.plugin_types:
            for ep in metadata.entry_points(
                group=f"{type_info.base_class.entry_point_prefix}.{type_info.base_class.__name__}"
            ):
                result[ep.value] = ep.name
        return result

    def resolve_ep_name(self, val: Any) -> str:
        """Return the entry-point name for a class object or ``module:class`` string."""
        if isinstance(val, type):
            key = f"{val.__module__}:{val.__name__}"
        elif isinstance(val, str) and ":" in val:
            key = val
        else:
            return str(val) if val is not None else ""
        return self.ep_value_to_name.get(key, key)


server_info = ServerInfo()
