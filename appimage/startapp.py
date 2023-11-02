import code
from configparser import ConfigParser
import os
import sys
from typing import Any, Optional

if 'APPDIR' not in os.environ:
    sys.exit("APPDIR variable not exported!")

APPDIR: str = os.environ.get('APPDIR')
ARGV0: Optional[str] = os.environ.get('ARGV0')
CMD_NAME: Optional[str] = f"command:{os.path.basename(ARGV0)}" if ARGV0 else None

SHIV_INTERPRETER: Optional[str] = os.environ.get('SHIV_INTERPRETER')
SHIV_ENTRY_POINT: Optional[str] = os.environ.get('SHIV_ENTRY_POINT')


def import_from(moule_name:str, function_name: str) -> Any:
    try:
        module = __import__(moule_name, fromlist=[function_name])
    except ModuleNotFoundError:
        sys.exit(f"Module '{moule_name}' does not exist in AppImage")
    try:
        return getattr(module, function_name)
    except AttributeError:
        sys.exit(f"Module '{moule_name}' has not function '{function_name}'")


def start_emulator() -> None:

    config = ConfigParser()
    if not os.path.isfile(os.path.join(APPDIR, 'appimage.ini')):
        sys.exit("No appimage.ini configuration file found in AppImage")
    config.read(os.path.join(APPDIR, 'appimage.ini'))

    if not config.has_section('appimage'):
        sys.exit("Missing 'appimage' section in appimage.ini")

    ALLOW_ENV = config.getboolean('appimage', 'allow_env', fallback=False)
    DEFAULT_CMD = config.get('appimage', 'default_command', fallback=None)
    if DEFAULT_CMD and not DEFAULT_CMD.startswith('command:'):
        DEFAULT_CMD = f"command:{DEFAULT_CMD}"

    entry_point: Optional[str] = None
    if CMD_NAME and config.has_section(CMD_NAME):
        entry_point = config.get(CMD_NAME, 'entry_point')
    elif DEFAULT_CMD and config.has_section(DEFAULT_CMD):
        entry_point = config.get(DEFAULT_CMD, 'entry_point')
    elif ALLOW_ENV and SHIV_ENTRY_POINT:
        if not config.getboolean('appimage', 'unrestrict_entry_points', fallback=False):
            for section in config.sections():
                if section.startswith("command:") and config.get(section, 'entry_point') == SHIV_ENTRY_POINT:
                    break
            else:
                sys.exit(f"Entry-points are restricted! {SHIV_ENTRY_POINT} not defined")
        entry_point = SHIV_ENTRY_POINT
    elif (
        config.getboolean('appimage', 'allow_interpreter', fallback=False)
        and (
            not entry_point or (ALLOW_ENV and SHIV_INTERPRETER)
        )    
    ):  
        code.interact(banner=config.get('appimage', 'interactive_prompt', fallback=None))
        return
    else:
        sys.exit("interactive interpreter disabled and no default entrypoint set!")

    # try to load the module
    try:
        module_name, function_name = entry_point.split(":")
    except Exception:
        sys.exit(f"failed to parse entrypoint '{entry_point}'")
    func = import_from(module_name, function_name)
    func()

if __name__ == "__main__":
    start_emulator()