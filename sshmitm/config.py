import os

from sshmitm.moduleparser.enhanced_configparser import ExtendedConfigParser

_config_paths = [
    "/etc/ssh-mitm.ini",
    "/etc/sshmitm.ini",
    os.path.expanduser("~/ssh-mitm.ini"),
    os.path.expanduser("~/sshmitm.ini"),
]

CONFIGFILE = ExtendedConfigParser(
    productionini=next((p for p in _config_paths if os.path.isfile(p)), None),
    package="sshmitm",
    env_name="SSHMITM_CONFIG",
    ignore_missing_default_config=False,
)
