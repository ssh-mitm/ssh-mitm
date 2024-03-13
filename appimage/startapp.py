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

from configparser import ConfigParser
from functools import cached_property
import os
import sys
from importlib.metadata import entry_points, EntryPoint
from typing import Dict, Optional


DEFAULT_CONFIG = """
[appimage]
entry_point =
"""


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
        if os.path.isfile(os.path.join(self.appdir, "appimage.ini")):
            self.config.read(os.path.join(self.appdir, "appimage.ini"))

        self.default_ep = self.config.get("appimage", "entry_point", fallback=None)
        argv0_complete = os.environ.get("ARGV0")
        self.argv0 = os.path.basename(argv0_complete) if argv0_complete else None
        self.env_ep = os.environ.get("APP_ENTRY_POINT")
        self.app_interpreter = os.environ.get("APP_INTERPRETER")

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
            os.environ["APPDIR"] = os.path.dirname(__file__)
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

        if self.argv0 and self.argv0 in self.entry_points:
            return self.entry_points[self.argv0]
        if self.env_ep and self.env_ep in self.entry_points:
            return self.entry_points[self.env_ep]
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
        args = [sys.executable]
        args.extend(sys.argv[1:])
        os.execvp(sys.executable, args)  # nosec

    def start(self) -> None:
        """
        Determine the entry point and start it. If an interpreter is requested via
        environment variables, or if no entry point is found, it starts an interpreter.
        Otherwise, it starts the determined entry point.
        """
        if sys.version_info < (3, 10):
            sys.exit(f"App starter for {self.argv0} requires Python 3.10 or later")
        if (
            (  # pylint: disable=too-many-boolean-expressions
                not self.get_entry_point(ignore_default=True) and self.app_interpreter
            )
            or (not self.default_ep and not self.env_ep and not self.get_entry_point())
            or self.argv0 in ["python", "python3", f"python3.{sys.version_info[1]}"]
        ):
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
    appstarter = AppStarter()
    try:
        appstarter.start()
    except AppStartException as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    start_entry_point()
