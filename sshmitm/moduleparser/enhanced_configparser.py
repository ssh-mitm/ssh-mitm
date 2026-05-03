# -*- coding: utf-8 -*-

from configparser import ConfigParser
import inspect
import logging
import os
import pickle  # nosec
import pkg_resources
from typing import (
    cast,
    Any,
    Optional,
    List,
    Union,
    Text,
    Type
)

class DefaultConfigNotFound(Exception):
    pass


class ExtendedConfigParser(ConfigParser):

    def __init__(
        self,
        productionini: Optional[Text] = None,
        defaultini: Text = 'default.ini',
        package: Optional[Text] = None,
        env_name: Text = 'ENHANCED_CONFIG_FILE',
        modules_from_file: bool = False,
        ignore_missing_default_config: bool = False
    ):
        super().__init__(allow_no_value=True)
        self.defaultini: Text = defaultini
        self.package: Optional[Text] = package
        self.ignore_missing_default_config: bool = ignore_missing_default_config
        self.default_config: Optional[Text] = self._get_default_config()
        self.production_config: Optional[Text] = None
        self.configfiles: List[Text] = []
        self.modules_from_file: bool = modules_from_file

        self._read_default_config()

        if productionini:
            self.production_config = productionini
        elif self.has_section('productionconfig') and self.has_option('productionconfig', 'configpath'):
            self.production_config = self.get('productionconfig', 'configpath')

        if env_name in os.environ:
            self.production_config = os.environ[env_name]

        if self.production_config:
            self.append(self.production_config)

    def _get_default_config(self) -> Optional[Text]:
        packages = []
        if self.package:
            packages.append(self.package)
        for frame in inspect.stack():
            frame_packagename = frame[0].f_globals['__name__'].split('.')[0]
            if frame_packagename != 'enhancements':
                packages.append(frame_packagename)
                break
        for packagename in packages:
            defaultconfig = pkg_resources.resource_filename(packagename, '/'.join(('data', self.defaultini)))
            if os.path.isfile(defaultconfig):
                return defaultconfig
        if not self.ignore_missing_default_config:
            raise DefaultConfigNotFound()
        logging.debug("mising default config")
        return None

    def _read_default_config(self) -> None:
        if self.default_config:
            logging.debug("Using default config: %s", self.default_config)
            self.append(self.default_config)

    def read(self, filenames: Any, encoding: Optional[Text] = 'utf-8') -> List[Text]:
        try:
            return super().read(filenames, encoding=encoding)
        except Exception:
            logging.exception("error reading %s", filenames)
            return []

    def copy(self) -> 'ExtendedConfigParser':
        """ create a copy of the current config
        """
        return cast('ExtendedConfigParser', pickle.loads(pickle.dumps(self)))  # nosec

    def append(self, configpath: Text) -> None:
        self.configfiles.append(configpath)
        if not configpath:
            return
        if os.path.isfile(configpath):
            logging.debug("using production configfile: %s", configpath)
            self.read(configpath)
        else:
            logging.warning(
                "production config file '%s' does not exist or is not readable.",
                configpath
            )

    def getlist(self, section: Text, option: Text, sep: Text = ',', chars: Optional[Text] = None) -> List[Text]:
        return [chunk.strip(chars) for chunk in self.get(section, option).split(sep) if chunk]

    def getboolean_or_string(self, section: Text, option: Text) -> Union[bool, Text]:
        try:
            return self.getboolean(section, option)
        except ValueError:
            return self.get(section, option)