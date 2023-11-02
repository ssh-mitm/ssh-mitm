import code
from configparser import ConfigParser
import os
import sys
from typing import Any, Optional

# set APPDIR if not already exported from AppRun
if 'APPDIR' not in os.environ:
    os.environ['APPDIR'] = os.path.dirname(__file__)

# try to get environment variables
# some of the variables are compatible with shiv
APPDIR: str = os.environ.get('APPDIR')
ARGV0: Optional[str] = os.environ.get('ARGV0')
CMD_NAME: Optional[str] = f"command:{os.path.basename(ARGV0)}" if ARGV0 else None

APP_INTERPRETER: Optional[str] = os.environ.get('APP_INTERPRETER')
if not APP_INTERPRETER:
    APP_INTERPRETER: Optional[str] = os.environ.get('SHIV_INTERPRETER')
APP_ENTRY_POINT: Optional[str] = os.environ.get('APP_ENTRY_POINT')
if not APP_ENTRY_POINT:
    APP_ENTRY_POINT: Optional[str] = os.environ.get('SHIV_ENTRY_POINT')


def import_from(moule_name: str, function_name: str) -> Any:
    """load a module and return the function from the entry point"""
    try:
        module = __import__(moule_name, fromlist=[function_name])
    except ModuleNotFoundError:
        sys.exit(f"Module '{moule_name}' does not exist in AppImage")
    try:
        return getattr(module, function_name)
    except AttributeError:
        sys.exit(f"Module '{moule_name}' has not function '{function_name}'")


def start_entry_point() -> None:
    """execute the entryp point"""

    # read the config file
    config = ConfigParser()
    if not os.path.isfile(os.path.join(APPDIR, 'appimage.ini')):
        sys.exit("No appimage.ini configuration file found in AppImage")
    config.read(os.path.join(APPDIR, 'appimage.ini'))

    # check if the config file has an appimage section
    if not config.has_section('appimage'):
        sys.exit("Missing 'appimage' section in appimage.ini")

    # get appimage settings
    allow_env = config.getboolean('appimage', 'allow_env', fallback=False)
    default_cmd = config.get('appimage', 'default_command', fallback=None)
    if default_cmd and not default_cmd.startswith('command:'):
        default_cmd = f"command:{default_cmd}"

    # get the entry point from config file
    entry_point: Optional[str] = None
    if CMD_NAME and config.has_section(CMD_NAME):
        entry_point = config.get(CMD_NAME, 'entry_point')
    elif default_cmd and config.has_section(default_cmd):
        entry_point = config.get(default_cmd, 'entry_point')
    elif allow_env and APP_ENTRY_POINT:
        if not config.getboolean('appimage', 'unrestrict_entry_points', fallback=False):
            for section in config.sections():
                if section.startswith("command:") and config.get(section, 'entry_point') == APP_ENTRY_POINT:
                    break
            else:
                sys.exit(f"Entry-points are restricted! {APP_ENTRY_POINT} not defined")
        entry_point = APP_ENTRY_POINT
    elif (
        config.getboolean('appimage', 'allow_interpreter', fallback=False)
        and (
            not entry_point or (allow_env and APP_INTERPRETER)
        )
    ):
        code.interact(banner=config.get('appimage', 'interactive_prompt', fallback=None))
        return
    else:
        sys.exit("interactive interpreter disabled and no default entrypoint set!")

    # try to load the module
    try:
        module_name, function_name = entry_point.split(":")
    except ValueError:
        sys.exit(f"failed to parse entrypoint '{entry_point}'")
    func = import_from(module_name, function_name)
    func()


if __name__ == "__main__":
    start_entry_point()
