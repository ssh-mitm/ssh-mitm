"""
This module provides a set of tools for SSH Man-In-The-Middle attacks. The module provides a main method that parses the provided command line arguments and invokes the corresponding subcommand.

Class: SubCommand
=================

The SubCommand class represents a subcommand in the SSH-MITM tool. It holds the implementation of the subcommand and the initialization of the corresponding parser for command line arguments.

Properties
----------

* run_func: function to run for the subcommand. It takes in the parsed command line arguments as input.
* parser_func: function to initialize the command line argument parser for the subcommand.
* help: help string for the subcommand.


Function: main
--------------

The main function is the entry point of the SSH-MITM tools. It provides a high-level overview of all available subcommands, parses the command line arguments, sets up logging, initializes the subcommand and executes the corresponding run function.

The main method takes in no inputs and returns nothing. It only has side effects such as setting up logging, parsing the command line arguments, and invoking the appropriate subcommand implementation.
Arguments

The following command line arguments are supported by the main method:

* -V, --version: prints the version information of the SSH-MITM tools.
* -d, --debug: provides more verbose output of status information.
* --paramiko-log-level: sets the log level for the paramiko library.
* --disable-workarounds: disables the paramiko workarounds.

The main method also supports subcommands. The specific subcommands and their arguments
are defined by the parser_func properties of the corresponding SubCommand instances.
"""

from argparse import Namespace
import logging
import os
import sys
from typing import Callable

from paramiko import Transport

from rich.logging import RichHandler
from rich.highlighter import NullHighlighter

from sshmitm.logging import PlainJsonFormatter, Colors, FailSaveLogStream
from sshmitm.moduleparser import ModuleParser
from sshmitm.workarounds import transport, monkeypatch
from sshmitm import __version__ as ssh_mitm_version
from sshmitm.server.cli import init_server_parser, run_server
from sshmitm.audit.cli import init_audit_parser, run_audit


class SubCommand():
    """
    This class represents a subcommand, which contains a function that is run and a parser that is used to parse arguments.

    :param run_func: A callable function that runs the subcommand
    :type run_func: Callable[[Namespace], None]
    :param parser_func: A callable function that generates the argument parser for the subcommand
    :type parser_func: Callable[[ModuleParser], None]
    :param help: A string that describes the subcommand
    :type help: str
    """

    def __init__(
        self,
        run_func: Callable[[Namespace], None],
        parser_func: Callable[[ModuleParser], None],
        config_section: str,
        help: str  # pylint: disable=redefined-builtin
    ):
        self.run_func = run_func
        self.config_section = config_section
        self.help = help
        self.parser_func = parser_func


def main() -> None:
    """
    Main function of the SSH-MITM tools, it provides a CLI interface to use the `audit` and `server` subcommands.

    :return: None
    :rtype: None
    """
    available_subcommands = {
        'audit': SubCommand(
            run_func=run_audit,
            parser_func=init_audit_parser,
            config_section='Audit',
            help='audit tools for ssh servers'
        ),
        'server': SubCommand(
            run_func=run_server,
            parser_func=init_server_parser,
            config_section='SSH-Server-Modules',
            help='start the ssh-mitm server'
        )
    }
    prog_name = os.path.basename(
        os.environ.get('ARGV0', 'ssh-mitm')
    )
    if os.environ.get('container'):
        prog_name = 'at.ssh_mitm.server'

    parser = ModuleParser(
        prog=prog_name,
        description='SSH-MITM Tools',
        allow_abbrev=False,
        config_section='SSH-MITM'
    )
    parser_group = parser.add_argument_group(
        'SSH-MITM',
        'global options for SSH-MITM'
    )
    parser_group.add_argument(
        '-V', '--version',
        action='version',
        version=f"SSH-MITM {ssh_mitm_version}"
    )
    parser_group.add_argument(
        '-d',
        '--debug',
        dest='debug',
        default=False,
        action='store_true',
        help='More verbose output of status information'
    )
    parser_group.add_argument(
        '--paramiko-log-level',
        dest='paramiko_log_level',
        default='warning',
        choices=['warning', 'info', 'debug'],
        help='set paramikos log level'
    )
    parser_group.add_argument(
        '--disable-workarounds',
        dest='disable_workarounds',
        action='store_true',
        help='disable paramiko workarounds'
    )
    parser.add_argument(
        '--log-format',
        dest='log_format',
        default="text",
        choices=['text', 'json'],
        help='defines the log output format (json will suppress stdout)'
    )

    subparsers = parser.add_subparsers(title='Available commands', dest="subparser_name", metavar='subcommand')
    subparsers.required = True
    for sc_name, sc_item in available_subcommands.items():
        sc_item.parser_func(
            # TODO: fix 'config_section' argument for suparser not known to mypy
            subparsers.add_parser(
                sc_name,
                allow_abbrev=False,
                help=sc_item.help,
                config_section=sc_item.config_section  # type: ignore
            )
        )

    args = parser.parse_args()

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    if args.log_format == 'json' or not sys.stdout.isatty():
        Colors.stylize_func = False
        root_logger.handlers.clear()
        log_handler = logging.StreamHandler(
            stream=FailSaveLogStream(debug=args.debug)
        )
        formatter = PlainJsonFormatter()  # type: ignore
        log_handler.setFormatter(formatter)
        root_logger.addHandler(log_handler)
    else:
        Colors.stylize_func = True
        root_logger.handlers.clear()
        root_logger.addHandler(RichHandler(
            highlighter=NullHighlighter(),
            markup=False,
            rich_tracebacks=True,
            enable_link_path=args.debug,
            show_path=args.debug
        ))

    if not args.disable_workarounds:
        monkeypatch.patch_thread()
        Transport.run = transport.transport_run  # type: ignore # pylint: disable=protected-access
        Transport._send_kex_init = transport.transport_send_kex_init  # type: ignore # pylint: disable=protected-access

    if args.paramiko_log_level == 'debug':
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    elif args.paramiko_log_level == 'info':
        logging.getLogger("paramiko").setLevel(logging.INFO)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    try:
        available_subcommands[args.subparser_name].run_func(args)
    except (AttributeError, KeyError):
        logging.exception("can not run subcommand - invalid subcommand name")
        sys.exit(1)


if __name__ == '__main__':
    main()
