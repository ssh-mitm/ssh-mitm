from argparse import Namespace
import logging
import sys
import os
from typing import Optional, Text, cast, Callable

from enhancements.modules import ModuleParser

from paramiko import Transport

from rich.logging import RichHandler
from rich.highlighter import NullHighlighter
from typeguard import typechecked

from sshmitm.workarounds import dropbear
from sshmitm.__version__ import version as ssh_mitm_version
from sshmitm.server.cli import init_server_parser, run_server
from sshmitm.audit.cli import init_audit_parser, run_audit


class SubCommand():

    @typechecked
    def __init__(
        self, 
        run_func: Callable[[Namespace], None],
        parser_func: Callable[[ModuleParser], None],
        help: Text
    ):
        self.run_func = run_func
        self.help = help
        self.parser_func = parser_func



@typechecked
def run() -> None:

    available_subcommands = {
        'audit': SubCommand(
            run_func=run_audit,
            parser_func=init_audit_parser,
            help='audit tools for ssh servers'
        ),
        'server': SubCommand(
            run_func=run_server,
            parser_func=init_server_parser,
            help='start the ssh-mitm server'
        )
    }

    if os.environ.get('APPIMAGE', None):
        # if running as appimage, remove empty arguments
        if len(sys.argv) == 2 and sys.argv[-1] == '':
            sys.argv = sys.argv[:-1]

    parser = ModuleParser(
        description='SSH-MITM Tools',
        version=f"SSH-MITM {ssh_mitm_version}",
        autocomplete=True,
        modules_from_file=True,
        allow_abbrev=False
    )
    parser.add_argument(
        '-d',
        '--debug',
        dest='debug',
        default=False,
        action='store_true',
        help='More verbose output of status information'
    )
    parser.add_argument(
        '--paramiko-log-level',
        dest='paramiko_log_level',
        default='warning',
        choices=['warning', 'info', 'debug'],
        help='set paramikos log level'
    )
    parser.add_argument(
        '--disable-workarounds',
        dest='disable_workarounds',
        action='store_true',
        help='disable paramiko workarounds'
    )

    
    subparsers = parser.add_subparsers(title='Available commands', dest="subparser_name", metavar='subcommand')
    subparsers.required = True
    for sc_name, sc_item in available_subcommands.items():
        sc_item.parser_func(
            subparsers.add_parser(
                sc_name,
                allow_abbrev=False,
                help=sc_item.help
            )
        )

    args = parser.parse_args()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    root_logger.handlers.clear()
    root_logger.addHandler(RichHandler(
        highlighter=NullHighlighter(),
        markup=False,
        rich_tracebacks=True,
        enable_link_path=args.debug,
        show_path=args.debug
    ))

    if not args.disable_workarounds:
        Transport.run = dropbear.transport_run  # type: ignore

    if args.paramiko_log_level == 'debug':
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    elif args.paramiko_log_level == 'info':
        logging.getLogger("paramiko").setLevel(logging.INFO)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    try:
        available_subcommands[args.subparser_name].run_func(args=args)
    except (AttributeError, KeyError):
        logging.exception("can not run subcommand - invalid subcommand name")
        sys.exit(1)


def main() -> None:
    run()

def audit() -> None:
    run('audit')

def server() -> None:
    run('server')


if __name__ == '__main__':
    main()
