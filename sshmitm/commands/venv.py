import os
import argparse
from importlib.metadata import entry_points
import sys
from venv import EnvBuilder
from typing import TYPE_CHECKING, Optional

from sshmitm.moduleparser import SubCommand

if TYPE_CHECKING:
    from types import SimpleNamespace


SYMLINK_TARGET = "python3"


def patch_appimage_venv(context: "SimpleNamespace") -> None:
    # if executed as AppImage override python symlink
    # this is not relevant for extracted AppImages
    appimage_path = os.environ.get("APPIMAGE")
    appdir = os.environ.get("APPDIR")
    if not appimage_path or not appdir or sys.version_info < (3, 10):
        sys.exit("venv command only supported by AppImages")

    # replace symlink to appimage instead of python executable
    python_path = os.path.join(context.bin_path, SYMLINK_TARGET)
    os.remove(python_path)
    os.symlink(appimage_path, python_path)

    eps = entry_points()
    scripts = eps.select(group="console_scripts")  # type: ignore[attr-defined, unused-ignore] # ignore old python < 3.10
    for ep in scripts:
        ep_path = os.path.join(context.bin_path, ep.name)
        if os.path.isfile(ep_path):
            continue
        os.symlink(SYMLINK_TARGET, ep_path)


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
        self.parser.add_argument(
            "--without-pip",
            dest="with_pip",
            default=True,
            action="store_false",
            help="Skips installing or upgrading pip in the "
            "virtual environment (pip is bootstrapped "
            "by default)",
        )

    def execute(self, args: argparse.Namespace) -> None:
        if not hasattr(EnvBuilder, "setup_python_original"):
            # ignore type errors from monkey patching
            EnvBuilder.setup_python_original = EnvBuilder.setup_python  # type: ignore[attr-defined]
            EnvBuilder.setup_python = setup_python_patched  # type: ignore[method-assign]

        builder = EnvBuilder(symlinks=True)
        for d in args.dirs:
            builder.create(d)
