"""Module for initializing applications within an AppImage via AppRun.

This module is designed to be invoked by the AppRun script of an AppImage and is not intended 
for direct execution. The module includes the AppStarter class, which orchestrates the application 
startup process based on configurations defined in a .ini file, controlling environment variables, 
interpreter access, entry point restrictions, and default commands.

The .ini configuration file must be named 'appimage.ini' and located within the root firectory 
of an AppImage next to the AppRun. 

The provided AppRun bash script sets up the necessary environment and invokes the application 
using this module. It should be located at the root of the AppImage filesystem.

AppRun Script Overview:
-----------------------
The AppRun script performs the following actions:

1. Sets the APPDIR environment variable if not already set, which specifies the AppImage's mount 
   point directory.

2. Exports additional environment variables required by the Python application.

3. Executes the Python interpreter bundled within the AppImage, passing along any arguments to 
   the startapp.py script, which in turn utilizes this module to launch the application.

AppRun Bash Script:
-------------------
#!/bin/bash

# Set APPDIR when running directly from the AppDir
if [ -z $APPDIR ]; then
    export APPDIR=$(readlink -f $(dirname "$0"))
fi

# Export environment variables for the Python application

# Start the Python application and pass arguments
exec $APPDIR/python/bin/python3 $APPDIR/startapp.py $@

Configuration File Format:
--------------------------
[appimage]
allow_env = True                # Allow environment variables to define entry points
allow_interpreter = True        # Enable starting an interactive Python interpreter
restrict_entry_points = False   # Restrict usage to predefined entry points if True
default_command = ssh-mitm      # Set the default command if none is specified

[command:ssh-mitm]              # Configuration for 'ssh-mitm' command
entry_point = sshmitm.cli:main  # Designates entry point for 'ssh-mitm'

Intended Usage:
---------------
This module is used within an AppImage environment, with the AppRun entry point calling the 
`start_entry_point` function provided by this module. AppStarter reads the configurations, 
determines the appropriate entry point, and initiates the application.
"""


from configparser import ConfigParser
import os
import sys
from typing import Any, Optional


DEFAULT_CONFIG = """
[appimage]
allow_env = True
restrict_entry_points = False
allow_interpreter = True
default_command = 
"""

class AppStartException(Exception):
    """Base exception class for errors during the app start process."""


class EntryPointPermissionError(AppStartException):
    """Exception raised when there is a permission error with the entry point."""


class InvalidEntryPointFormat(AppStartException):
    """Exception raised for invalid entry point format."""


class AppStarter:
    """
    Class responsible for managing the application start process, including 
    reading the configuration, determining the correct entry point, and 
    executing the application.
    """

    def __init__(self):
        """
        Initializes the AppStarter instance by reading the default configuration
        and any existing 'appimage.ini' configuration file in the APPDIR.
        """
        self.config = ConfigParser()
        self.config.read_string(DEFAULT_CONFIG)
        if os.path.isfile(os.path.join(self.appdir, 'appimage.ini')):
            self.config.read(os.path.join(self.appdir, 'appimage.ini'))

    @property
    def appdir(self) -> str:
        """
        Get the application directory from the 'APPDIR' environment variable.
        If 'APPDIR' is not set in the environment, it defaults to the directory
        containing the current file (__file__).

        Returns:
            str: The path to the application directory.
        """
        if 'APPDIR' not in os.environ:
            os.environ['APPDIR'] = os.path.dirname(__file__)
        return os.environ['APPDIR']
        
    @property
    def env_allowed(self) -> bool:
        """
        Check if the environment variables are allowed to be used based on the
        configuration in 'appimage.ini'.

        Returns:
            bool: True if environment variables are allowed, False otherwise.
        """
        return self.config.getboolean('appimage', 'allow_env', fallback=False)
    
    @property
    def default_command(self) -> Optional[str]:
        """
        Retrieve the default command from the configuration if specified.
        The command must be in the format 'command:entry_point' where
        'entry_point' is defined in the configuration under the respective
        'command:' section.

        Returns:
            Optional[str]: The default entry point command if available, None otherwise.
        """
        default_cmd = self.config.get('appimage', 'default_command', fallback=None)
        if default_cmd and not default_cmd.startswith('command:'):
            default_cmd = f"command:{default_cmd}"
        if (
            default_cmd
            and self.config.has_section(default_cmd) 
            and self.config.has_option(default_cmd, 'entry_point')
        ):
            return self.config.get(default_cmd, 'entry_point')
        return None

    @property
    def argv0_command(self) -> Optional[str]:
        """
        Fetch the command corresponding to the 'ARGV0' environment variable.
        'ARGV0' typically contains the name of the script being executed.
        It retrieves the entry point for this command from the configuration file.

        Returns:
            Optional[str]: The entry point for 'ARGV0' if defined, None otherwise.
        """
        argv0 = os.environ.get('ARGV0', '')
        argv0_section = f"command:{os.path.basename(argv0)}" if argv0 else None
        if (
            argv0_section 
            and self.config.has_section(argv0_section) 
            and self.config.has_option(argv0_section, 'entry_point')
        ):
            return self.config.get(argv0_section, 'entry_point')
        return None

    @property
    def env_command(self) -> Optional[str]:
        """
        Fetch the entry point from the environment variables 'APP_ENTRY_POINT'
        or 'SHIV_ENTRY_POINT' if they are set and allowed by the configuration.
        It checks if entry points are restricted and raises an exception if an
        unauthorized entry point is accessed.

        Returns:
            Optional[str]: The entry point specified in the environment, None if not allowed or not found.
        
        Raises:
            EntryPointPermissionError: If entry points are restricted and the specified one is not defined.
        """
        env_entry_point = os.environ.get('APP_ENTRY_POINT') or os.environ.get('SHIV_ENTRY_POINT')
        if self.argv0_command or not env_entry_point or not self.env_allowed:
            return None
        for section in self.config.sections():
            if (
                section.startswith("command:") 
                and self.config.has_option(section, 'entry_point')
                and self.config.get(section, 'entry_point') == env_entry_point
            ):
                return env_entry_point
        if self.config.getboolean('appimage', 'restrict_entry_points', fallback=True):
            raise EntryPointPermissionError(f"Entry-points are restricted! {env_entry_point} not defined")
        return env_entry_point

    def get_entry_point(self) -> Optional[str]:
        """
        Determine the entry point to be executed. It prioritizes the entry point
        in the following order: environment variable, 'ARGV0', default command
        specified in the configuration file.

        Returns:
            Optional[str]: The determined entry point to be used, None if none are defined.
        """
        commands = {
            'default': self.default_command,
            'argv0': self.argv0_command,
            'env': self.env_command
        }
        if commands['env']:
            return commands['env']
        if commands['argv0']:
            return commands['argv0']
        if commands['default']:
            return commands['default']
        return None

    def start_entry_point(self, entry_point: str) -> None:
        """
        Load a module and execute the function specified by the entry point.
        The entry point is a string in the 'module:function' format.

        Args:
            entry_point (str): The entry point string in the 'module:function' format.

        Raises:
            InvalidEntryPointFormat: If the entry point does not match the expected format.
        """
        try:
            module_name, function_name = entry_point.split(":")
        except ValueError:
            raise InvalidEntryPointFormat(f"'{entry_point}' does not match 'modulname:function' format!")
        module = __import__(module_name, fromlist=[function_name])
        func = getattr(module, function_name)
        sys.exit(func())

    def start_interpreter(self) -> None:
        """
        Start an interactive Python interpreter using the current Python executable
        if allowed by the configuration. It passes any additional arguments provided
        in the command line to the interpreter.

        Exits:
            The program exits with a message if the interactive console is not enabled.
        """
        if self.config.getboolean('appimage', 'allow_interpreter', fallback=False):
            args = [sys.executable]
            args.extend(sys.argv[1:])
            os.execvp(sys.executable, args)
        sys.exit("interactive console not enabled!")

    def start(self) -> None:
        """
        Determine the entry point and start it. If an interpreter is requested via
        environment variables, or if no entry point is found, it starts an interpreter.
        Otherwise, it starts the determined entry point.
        """
        entry_point = self.get_entry_point()
        if (
            os.environ.get('APP_INTERPRETER') 
            or os.environ.get('SHIV_INTERPRETER') 
            or not entry_point
        ):
            self.start_interpreter()
        self.start_entry_point(entry_point)
        

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
