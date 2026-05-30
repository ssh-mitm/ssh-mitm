"""ssh-mitm tutorial subcommand."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sshmitm.moduleparser import SubCommand

if TYPE_CHECKING:
    import argparse


class Tutorial(SubCommand):
    """interactive SSH-MITM tutorial"""

    def register_arguments(self) -> None:
        self.parser.add_argument(
            "--port",
            dest="port",
            type=int,
            default=0,
            metavar="PORT",
            help="port for the tutorial web server (default: random free port)",
        )
        self.parser.add_argument(
            "--no-browser",
            dest="no_browser",
            action="store_true",
            help="start server without opening the browser automatically",
        )
        self.parser.add_argument(
            "--log",
            dest="log_file",
            default=None,
            metavar="FILE",
            help="write debug log to FILE",
        )

    def execute(self, args: argparse.Namespace) -> None:
        if args.log_file:
            logging.basicConfig(
                level=logging.DEBUG,
                format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                filename=args.log_file,
                filemode="w",
            )

        from sshmitm.tutorial._web import run
        from sshmitm.tutorial.tutorials import ALL_TUTORIALS

        run(ALL_TUTORIALS, port=args.port, open_browser=not args.no_browser)
