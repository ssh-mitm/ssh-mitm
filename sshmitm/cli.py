"""
CLI entrypoint and utilities for the SSH-MITM tools.

This module provides helper functions to load configuration and the `main`
function which implements the command-line interface. The CLI uses a
`ModuleParser` to load and dispatch subcommands (for example `audit` and
`server`). It also configures logging, optionally applies runtime workarounds
for Paramiko, and forwards the selected subcommand with parsed arguments.

The top-level responsibilities of this module are:

* Load default and user-provided configuration.
* Construct and configure the command-line parser.
* Initialize logging and optional compatibility workarounds.
* Execute the requested subcommand.

Note
----
The module intentionally performs several global side effects:
environment inspection, logging configuration, and monkeypatching of Paramiko
behavior when workarounds are enabled.
"""

import logging
import os
import sys
from configparser import ConfigParser

from paramiko import Transport

from sshmitm import __version__ as ssh_mitm_version
from sshmitm import project_metadata
from sshmitm.core.compat import resources
from sshmitm.core.logger import Colors, FailSaveLogStream, PlainJsonFormatter
from sshmitm.core.moduleparser import ModuleParser
from sshmitm.workarounds import monkeypatch, transport


def get_config() -> ConfigParser:
    """
    Load configuration for the application.

    This function builds a merged configuration using, in precedence order:
    1. The packaged default configuration shipped with the module.
    2. The first readable configuration file found in the `CONFIGFILE_PATH_LIST`.
    3. A configuration file pointed to by the environment variable defined in
       `CONFIG_ENV_VAR_NAME` (if it exists and is a file).

    The returned :class:`ConfigParser` contains the combined configuration.

    :returns: A ConfigParser with the merged configuration values.
    """
    configfile = ConfigParser()

    # Read the bundled default configuration from package resources.
    # This ensures there are sane defaults even when no external config exists.
    conf = (
        resources.files(project_metadata.MODULE_NAME)
        / project_metadata.MODULE_CONFIG_PATH
    )
    configfile.read_string(conf.read_text())

    # Search well-known locations for a production or user config file and read
    # the first one found. These paths are defined in project metadata.
    for configpath in project_metadata.CONFIGFILE_PATH_LIST:
        if os.path.isfile(configpath):
            configfile.read(configpath)
            break  # stop at the first config file found

    # If an environment variable explicitly points to a config file, prefer it
    # (but only if the path actually exists).
    sshmitm_config_env = os.environ.get(project_metadata.CONFIG_ENV_VAR_NAME)
    if sshmitm_config_env and os.path.isfile(sshmitm_config_env):
        configfile.read(sshmitm_config_env)

    return configfile


def main() -> None:
    """
    Main entry point for the SSH-MITM command-line tools.

    This function constructs a ModuleParser preloaded with configuration and
    global options, loads available subcommands, configures application logging
    (text or JSON), optionally applies Paramiko compatibility workarounds, and
    finally dispatches the chosen subcommand with the parsed arguments.

    The function performs several side effects:
    * Reads configuration from package resources and files.
    * Mutates global logging configuration and handlers.
    * May monkeypatch Paramiko internals when workarounds are enabled.

    The supported global CLI options include:
    * ``-V, --version`` — print version information and exit.
    * ``-d, --debug`` — enable debug mode for more verbose output.
    * ``--paramiko-log-level`` — set the log level for the Paramiko library.
    * ``--disable-workarounds`` — skip the Paramiko workaround monkeypatches.
    * ``--log-format`` — choose between textual or JSON log output.

    Subcommands are loaded via :class:`ModuleParser.load_subcommands` and are
    responsible for adding their own arguments and implementing the action
    to be executed.

    :raises SystemExit: on failure to run the requested subcommand.
    """
    # Choose a program name for help and usage output. Support container/runtime
    # environments where the original argv0 may be provided via ARGV0.
    prog_name = os.path.basename(os.environ.get("ARGV0", project_metadata.COMMAND_NAME))

    # If running inside a flatpak container, prefer the flatpak-style command name so
    # logs and usage messages are clearer in that environment.
    if os.environ.get("container"):  # noqa: SIM112 - checked intentionally
        prog_name = project_metadata.COMMAND_NAME_FLATPAK

    # Initialize the ModuleParser which also holds configuration and is used to
    # discover/install subcommands.
    parser = ModuleParser(
        entry_point_prefix=project_metadata.MODULE_NAME,
        config=get_config(),
        prog=prog_name,
        description=f"{project_metadata.PROJECT_NAME} Tools",
        allow_abbrev=False,
        config_section=project_metadata.PROJECT_NAME,
    )

    # Global parser group for shared options (version, debug, etc.).
    parser_group = parser.add_argument_group(
        project_metadata.PROJECT_NAME,
        description=f"global options for {project_metadata.PROJECT_NAME}",
    )

    # Standard version action prints package name and version, then exits.
    parser_group.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"{project_metadata.PROJECT_NAME} {ssh_mitm_version}",
    )

    # Debug flag toggles verbose logging for troubleshooting.
    parser_group.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        help=f"Enables {project_metadata.PROJECT_NAME}'s debug mode, providing more verbose output of status information and internal processes.",
    )

    # Paramiko log level selection controls the verbosity of the underlying SSH library.
    parser_group.add_argument(
        "--paramiko-log-level",
        dest="paramiko_log_level",
        choices=["warning", "info", "debug"],
        help="Sets the log level for Paramiko, the underlying SSH library. Controls the verbosity of Paramiko's logging output.",
    )

    # Optionally disable compatibility monkeypatches; helpful for debugging or
    # when running against newer/untested Paramiko versions.
    parser_group.add_argument(
        "--disable-workarounds",
        dest="disable_workarounds",
        action="store_true",
        help="Disables workarounds for compatibility issues with certain SSH clients. Some clients may require these workarounds to function correctly.",
    )

    # Global logging format option: either human-friendly text or structured JSON.
    parser.add_argument(
        "--log-format",
        dest="log_format",
        choices=["text", "json"],
        help="Defines the format of the log output. Using `json` suppresses standard output and formats logs as JSON.",
    )

    # Dynamically load subcommands registered in the modules discovered by ModuleParser.
    parser.load_subcommands()

    # Parse CLI arguments and select subcommand.
    args = parser.parse_args()

    # Root logger configuration: DEBUG when debug is requested, otherwise INFO.
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    # Configure logging output format. If JSON format requested or stdout is not
    # a TTY, prefer JSON output and a fail-safe log stream that doesn't raise.
    if args.log_format == "json" or not sys.stdout.isatty():
        # Disable colored/stylized output because JSON logs must be plain text.
        Colors.stylize_func = False

        # Clear any existing handlers to avoid duplicate logging entries.
        root_logger.handlers.clear()

        # Use a stream handler that wraps stdout/stderr in a safe way for logging.
        log_handler = logging.StreamHandler(stream=FailSaveLogStream(debug=args.debug))

        # PlainJsonFormatter formats records as compact JSON objects.
        formatter = PlainJsonFormatter()  # type: ignore[no-untyped-call]
        log_handler.setFormatter(formatter)
        root_logger.addHandler(log_handler)
    else:
        # For human-friendly text output, activate the fail-safe stream formatting
        # which configures colorized output and handles intermittent stream errors.
        FailSaveLogStream.activate_format(debug=args.debug)

    # Apply Paramiko compatibility monkeypatches unless explicitly disabled.
    if not args.disable_workarounds:
        # Patch threading behavior or other process-level shims required by some transports.
        monkeypatch.patch_thread()

        # Replace Transport.run and Transport._send_kex_init with compatibility wrappers.
        # These assignments intentionally modify Paramiko internals for workaround behavior.
        Transport.run = transport.transport_run  # type: ignore[method-assign] # pylint: disable=protected-access
        Transport._send_kex_init = transport.transport_send_kex_init  # type: ignore[attr-defined] # pylint: disable=protected-access

    # Set Paramiko's own logger level according to CLI option.
    if args.paramiko_log_level == "debug":
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    elif args.paramiko_log_level == "info":
        logging.getLogger("paramiko").setLevel(logging.INFO)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    # Execute the chosen subcommand and handle common failure modes.
    try:
        # `execute_subcommand` is expected to locate the subcommand implementation
        # based on the parsed `subparser_name` and invoke it with `args`.
        parser.execute_subcommand(args.subparser_name, args)
    except (AttributeError, KeyError):
        # These exceptions commonly indicate an invalid or missing subcommand name.
        logging.exception("can not run subcommand - invalid subcommand name")
        sys.exit(1)


if __name__ == "__main__":
    # When executed as a script, run the CLI main entrypoint.
    main()
