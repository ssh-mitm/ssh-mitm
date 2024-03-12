from configparser import ConfigParser
import os
import argparse
from venv import EnvBuilder
from typing import TYPE_CHECKING, Optional

from sshmitm.moduleparser import SubCommand

if TYPE_CHECKING:
    from types import SimpleNamespace


DEFAULT_CONFIG = """
[appimage]
allow_env = True
restrict_entry_points = False
allow_interpreter = True
default_command =
"""


def patch_appimage_venv(context: "SimpleNamespace") -> None:
    # if executed as AppImage override python symlink
    # this is not relevant for extracted AppImages
    appimage_path = os.environ.get("APPIMAGE")
    appdir = os.environ.get("APPDIR")
    if not appimage_path or not appdir:
        return

    # replace symlink to appimage instead of python executable
    python_path = os.path.join(context.bin_path, "python3")
    os.remove(python_path)
    os.symlink(appimage_path, python_path)

    # create default command for application
    config = ConfigParser()
    config.read_string(DEFAULT_CONFIG)
    if os.path.isfile(os.path.join(appdir, "appimage.ini")):
        config.read(os.path.join(appdir, "appimage.ini"))
    default_command = config.get("appimage", "default_command")
    print(default_command)
    if default_command:
        os.symlink(appimage_path, os.path.join(context.bin_path, default_command))


def setup_python_patched(self: EnvBuilder, context: "SimpleNamespace") -> None:
    # call monkey patched function
    self.setup_python_original(context)  # type: ignore[attr-defined]
    patch_appimage_venv(context)


class SshMitmVenv(SubCommand):
    """Creates virtual Python environments in one or more target directories."""

    @classmethod
    def config_section(cls) -> Optional[str]:
        return None

    def register_arguments(self) -> None:
        self.parser.add_argument(
            "dirs",
            metavar="ENV_DIR",
            nargs="+",
            help="A directory to create the environment in.",
        )

    def execute(self, args: argparse.Namespace) -> None:
        if not hasattr(EnvBuilder, "setup_python_original"):
            # ignore type errors from monkey patching
            EnvBuilder.setup_python_original = EnvBuilder.setup_python  # type: ignore[attr-defined]
            EnvBuilder.setup_python = setup_python_patched  # type: ignore[method-assign]

        builder = EnvBuilder(
            system_site_packages=False,
            clear=False,
            symlinks=True,
            upgrade=False,
            with_pip=False,
            prompt=None,
            upgrade_deps=False,
        )
        for d in args.dirs:
            builder.create(d)
