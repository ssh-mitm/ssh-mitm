import inspect
import logging
import os
import pickle  # nosec
from configparser import ConfigParser
from importlib.resources import files
from typing import Any, cast


class DefaultConfigNotFound(Exception):
    pass


class ExtendedConfigParser(ConfigParser):

    def __init__(  # pylint: disable=too-many-arguments
        self,
        productionini: str | None = None,
        defaultini: str = "default.ini",
        package: str | None = None,
        env_name: str = "ENHANCED_CONFIG_FILE",
        modules_from_file: bool = False,
        ignore_missing_default_config: bool = False,
    ) -> None:
        super().__init__(allow_no_value=True)
        self.defaultini: str = defaultini
        self.package: str | None = package
        self.ignore_missing_default_config: bool = ignore_missing_default_config
        self.default_config: str | None = self._get_default_config()
        self.production_config: str | None = None
        self.configfiles: list[str] = []
        self.modules_from_file: bool = modules_from_file

        self._read_default_config()

        if productionini:
            self.production_config = productionini
        elif self.has_section("productionconfig") and self.has_option(
            "productionconfig", "configpath"
        ):
            self.production_config = self.get("productionconfig", "configpath")

        if env_name in os.environ:
            self.production_config = os.environ[env_name]

        if self.production_config:
            self.append(self.production_config)

    def _get_default_config(self) -> str | None:
        packages = []
        if self.package:
            packages.append(self.package)
        for frame in inspect.stack():
            frame_packagename = frame[0].f_globals["__name__"].split(".")[0]
            if frame_packagename != "enhancements":
                packages.append(frame_packagename)
                break
        for packagename in packages:
            defaultconfig = files(packagename) / "data" / self.defaultini
            if defaultconfig.is_file():  # Prüft, ob die Ressource als Datei existiert
                return str(defaultconfig)

        if not self.ignore_missing_default_config:
            raise DefaultConfigNotFound
        logging.debug("mising default config")
        return None

    def _read_default_config(self) -> None:
        if self.default_config:
            logging.debug("Using default config: %s", self.default_config)
            self.append(self.default_config)

    def read(self, filenames: Any, encoding: str | None = "utf-8") -> list[str]:
        try:
            return super().read(filenames, encoding=encoding)
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("error reading %s", filenames)
            return []

    def copy(self) -> "ExtendedConfigParser":
        """create a copy of the current config"""
        return cast(
            "ExtendedConfigParser",
            pickle.loads(pickle.dumps(self)),  # nosec  # noqa: S301
        )

    def append(self, configpath: str) -> None:
        self.configfiles.append(configpath)
        if not configpath:
            return
        if os.path.isfile(configpath):
            logging.debug("using production configfile: %s", configpath)
            self.read(configpath)
        else:
            logging.warning(
                "production config file '%s' does not exist or is not readable.",
                configpath,
            )

    def getlist(
        self, section: str, option: str, sep: str = ",", chars: str | None = None
    ) -> list[str]:
        return [
            chunk.strip(chars)
            for chunk in self.get(section, option).split(sep)
            if chunk
        ]

    def getboolean_or_string(self, section: str, option: str) -> bool | str:
        try:
            return self.getboolean(section, option)
        except ValueError:
            return self.get(section, option)
