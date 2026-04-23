"""SSH-MITM plugin inspection commands."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sshmitm.commands.pluginbrowser import run_browser
from sshmitm.moduleparser import SubCommand

if TYPE_CHECKING:
    import argparse


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
            run_browser()
        else:
            self.parser.print_help()
