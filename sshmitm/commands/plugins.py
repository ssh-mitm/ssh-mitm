"""SSH-MITM plugin inspection commands."""

from __future__ import annotations

import argparse
from configparser import ConfigParser
from importlib import resources

from sshmitm.cli import create_parser as _create_main_parser
from sshmitm.moduleparser import SubCommand
from sshmitm.moduleparser.parser import ModuleParser
from sshmitm.moduleparser.pluginbrowser import run_browser
from sshmitm.moduleparser.pluginbrowser.registry import plugin_registry
from sshmitm.moduleparser.plugininfo import (
    PluginTypeInfo,
    class_to_label,
    extract_groups,
)
from sshmitm.server.cli import SSHServerModules

_STANDARD_GROUPS: set[str | None] = {
    "positional arguments",
    "optional arguments",
    "options",
    None,
}


def _register_sshmitm_info() -> None:
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
    plugin_registry.register(plugin_types, general_groups)


def _load_default_cfg() -> ConfigParser:
    cfg = ConfigParser()
    conf = resources.files("sshmitm") / "data/default.ini"
    cfg.read_string(conf.read_text())
    return cfg


class Plugins(SubCommand):
    """manage and inspect SSH-MITM plugins"""

    @classmethod
    def config_section(cls) -> str | None:
        return None

    def register_arguments(self) -> None:
        subparsers = self.parser.add_subparsers(
            dest="plugins_command", metavar="COMMAND"
        )
        subparsers.add_parser(
            "show",
            help="open interactive plugin browser",
        )

    def execute(self, args: argparse.Namespace) -> None:
        command = getattr(args, "plugins_command", None)
        if command == "show":
            _register_sshmitm_info()
            run_browser(
                title="SSH-MITM Plugin Browser",
                tree_root_label="SSH-MITM",
                active_config_section="SSH-Server-Modules",
                default_cfg=_load_default_cfg(),
            )
        else:
            self.parser.print_help()
