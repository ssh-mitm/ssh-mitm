"""Module for initializing applications within an AppImage via AppRun.

This module is designed to be invoked by the AppRun script of an AppImage and is not intended
for direct execution. The module includes the AppStarter class, which orchestrates the application
startup process based on configurations defined in a .ini file, controlling environment variables,
interpreter access, entry point restrictions, and default commands.

The .ini configuration file must be named 'appimage.ini' and located within the root firectory
of an AppImage next to the AppRun.

The provided AppRun bash script sets up the necessary environment and invokes the application
using this module. It should be located at the root of the AppImage filesystem.

Configuration File Format:
--------------------------

[appimage]
entry_point = sshmitm.cli:main  # entry point which uses the module function syntax

or

[appimage]
entry_point = ssh-mitm  # entry point is set by entrypoint name

Intended Usage:
---------------

This module is used within an AppImage environment, with the AppRun entry point calling the
`start_entry_point` function provided by this module. AppStarter reads the configurations,
determines the appropriate entry point, and initiates the application.
"""

import argparse
import os
import sys
from configparser import ConfigParser
from functools import cached_property
from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING, Dict, Optional
from venv import EnvBuilder

from sshmitm.utils import resources

if TYPE_CHECKING:
    from types import SimpleNamespace


DEFAULT_CONFIG = """
[appimage]
entry_point =
"""


def patch_appimage_venv(context: "SimpleNamespace") -> None:
    symlink_target = "python3"
    # if executed as AppImage override python symlink
    # this is not relevant for extracted AppImages
    appimage_path = os.environ.get("APPIMAGE")
    appdir = os.environ.get("APPDIR")
    if not appimage_path or not appdir or sys.version_info < (3, 10):
        sys.exit("venv command only supported by AppImages")

    # replace symlink to appimage instead of python executable
    python_path = os.path.join(context.bin_path, symlink_target)
    os.remove(python_path)
    os.symlink(appimage_path, python_path)

    eps = entry_points()
    scripts = eps.select(group="console_scripts")  # type: ignore[attr-defined, unused-ignore] # ignore old python < 3.10
    for ep in scripts:
        ep_path = os.path.join(context.bin_path, ep.name)
        if os.path.isfile(ep_path):
            continue
        os.symlink(symlink_target, ep_path)


def setup_python_patched(self: EnvBuilder, context: "SimpleNamespace") -> None:
    # call monkey patched function
    self.setup_python_original(context)  # type: ignore[attr-defined]
    patch_appimage_venv(context)


class AppStartException(Exception):
    """Base exception class for errors during the app start process."""


class InvalidEntryPoint(AppStartException):
    """Exception raised for invalid entry point."""


class AppStarter:
    """
    Class responsible for managing the application start process, including
    reading the configuration, determining the correct entry point, and
    executing the application.
    """

    def __init__(self) -> None:
        """
        Initializes the AppStarter instance by reading the default configuration
        and any existing 'appimage.ini' configuration file in the APPDIR.
        """
        self.config = ConfigParser()
        self.config.read_string(DEFAULT_CONFIG)
        config_path = resources.files("sshmitm.data").joinpath("appimage.ini")
        self.config.read_string(config_path.read_text(encoding="utf-8"))

        self.default_ep = self.config.get("appimage", "entry_point", fallback=None)
        argv0_complete = os.environ.get("ARGV0")
        self.argv0 = os.path.basename(argv0_complete) if argv0_complete else None
        self.env_ep = os.environ.get("APP_ENTRY_POINT")
        self.virtual_env = os.environ.get("VIRTUAL_ENV")

    @cached_property
    def appdir(self) -> str:
        """
        Get the application directory from the 'APPDIR' environment variable.
        If 'APPDIR' is not set in the environment, it defaults to the directory
        containing the current file (__file__).

        Returns:
            str: The path to the application directory.
        """
        if "APPDIR" not in os.environ:
            os.environ["APPDIR"] = os.path.dirname(__file__)  # noqa: PTH120
        return os.environ["APPDIR"]

    @cached_property
    def entry_points(self) -> Dict[str, EntryPoint]:
        eps = entry_points()
        scripts = eps.select(group="console_scripts")  # type: ignore[attr-defined, unused-ignore] # ignore old python < 3.10
        script_eps = {}
        for ep in scripts:
            script_eps[ep.name] = ep
            script_eps[ep.value] = ep
        return script_eps

    def get_entry_point(self, *, ignore_default: bool = False) -> Optional[EntryPoint]:

        if self.env_ep and self.env_ep in self.entry_points:
            return self.entry_points[self.env_ep]
        if self.argv0 and self.argv0 in self.entry_points:
            return self.entry_points[self.argv0]
        if (
            not ignore_default
            and self.default_ep
            and self.default_ep in self.entry_points
        ):
            return self.entry_points[self.default_ep]
        return None

    def start_entry_point(self) -> None:
        """
        Load a module and execute the function specified by the entry point.
        The entry point is a string in the 'module:function' format.

        Raises:
            InvalidEntryPoint: If the entry point does not exist.
        """
        if self.virtual_env:
            sys.executable = os.path.join(self.virtual_env, "bin/python3")
        entry_point = self.get_entry_point()
        if entry_point:
            entry_point_loaded = entry_point.load()
            sys.exit(entry_point_loaded())

        error_msg = f"'{self.env_ep or self.default_ep or self.argv0}' is not a valid entry point!"
        raise InvalidEntryPoint(error_msg)

    def start_interpreter(self) -> None:
        """Start an interactive Python interpreter using the current Python executable.

        It passes any additional arguments provided in the command line to the interpreter.
        """
        args = [sys.executable, "-P"]
        args.extend(sys.argv[1:])
        os.execvp(  # nosec # noqa: S606 # Starting a process without a shell
            sys.executable, args
        )

    def create_venv(self, venv_dir: str) -> None:
        if not hasattr(EnvBuilder, "setup_python_original"):
            # ignore type errors from monkey patching
            EnvBuilder.setup_python_original = EnvBuilder.setup_python  # type: ignore[attr-defined]
            EnvBuilder.setup_python = setup_python_patched  # type: ignore[method-assign]

        builder = EnvBuilder(symlinks=True)
        builder.create(venv_dir)
        sys.exit()

    def parse_python_args(self) -> None:
        parser = argparse.ArgumentParser(add_help=False)
        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "--python-help",
            action="help",
            default=argparse.SUPPRESS,
            help="Show this help message and exit.",
        )
        group.add_argument(
            "--python-interpreter",
            dest="python_interpreter",
            action="store_true",
            help="start the python intrpreter",
        )
        group.add_argument(
            "--python-venv",
            dest="python_venv_dir",
            help="creates a virtual env pointing to the AppImage",
        )
        group.add_argument(
            "--python-entry-point",
            dest="python_entry_point",
            help="start a python entry point from console scripts (e.g. ssh-mitm)",
        )

        args, _ = parser.parse_known_args()
        if args.python_interpreter:
            sys.argv.remove("--python-interpreter")
            self.start_interpreter()
        if args.python_venv_dir:
            self.create_venv(args.python_venv_dir)
        if args.python_entry_point:
            sys.argv.remove("--python-entry-point")
            sys.argv.remove(args.python_entry_point)
            self.env_ep = args.python_entry_point

    def start(self) -> None:
        """
        Determine the entry point and start it. If an interpreter is requested via
        environment variables, or if no entry point is found, it starts an interpreter.
        Otherwise, it starts the determined entry point.
        """
        if sys.version_info < (3, 10):
            sys.exit(f"App starter for {self.argv0} requires Python 3.10 or later")
        self.parse_python_args()
        if (
            not self.default_ep and not self.env_ep and not self.get_entry_point()
        ) or self.argv0 in ["python", "python3", f"python3.{sys.version_info[1]}"]:
            self.start_interpreter()
        self.start_entry_point()


def start_entry_point() -> None:
    """
    Initiates the application start process by creating an instance of the AppStarter class
    and calling its start method. This function acts as an entry point to begin the application's
    execution flow.

    The `start` method of the AppStarter instance will determine the appropriate entry point
    from the available configurations and proceed to execute it. If the `start` method encounters
    any issues that it cannot handle (such as configuration errors, missing entry points, etc.),
    it will raise an AppStartException.
    """
    if not os.environ.get("APPDIR"):
        sys.exit("This module must be started from an AppImage!")
    appstarter = AppStarter()
    try:
        appstarter.start()
    except AppStartException as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    start_entry_point()
