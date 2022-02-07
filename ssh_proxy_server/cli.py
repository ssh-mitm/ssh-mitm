import logging
import sys
import os
from typing import cast

from enhancements.modules import ModuleParser

from paramiko import Transport

from rich.logging import RichHandler
from rich.highlighter import NullHighlighter
from typeguard import typechecked

from ssh_proxy_server.workarounds import dropbear
from ssh_proxy_server.__version__ import version as ssh_mitm_version
from ssh_proxy_server.server.cli import init_server_parser, run_server
from ssh_proxy_server.audit.cli import init_audit_parser, run_audit


@typechecked
def main() -> None:

    if os.environ.get('APPIMAGE', None):
        # if running as appimage, remove empty arguments
        if len(sys.argv) == 2 and sys.argv[-1] == '':
            sys.argv = sys.argv[:-1]

    parser = ModuleParser(
        description='SSH-MITM Tools',
        version=f"SSH-MITM {ssh_mitm_version}",
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

    parser_mitm_server: ModuleParser = cast(
        ModuleParser,
        subparsers.add_parser(
            'server',
            allow_abbrev=False,
            help='start the ssh-mitm server'
        )
    )
    init_server_parser(parser_mitm_server)
    parser_audit: ModuleParser = cast(
        ModuleParser,
        subparsers.add_parser(
            'audit',
            allow_abbrev=False,
            help='audit tools for ssh servers'
        )
    )
    init_audit_parser(parser_audit)

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

    if args.subparser_name == 'server':
        run_server(args=args)
    elif args.subparser_name == 'audit':
        run_audit(args=args)


if __name__ == '__main__':
    main()
