import os
from configparser import ConfigParser

from sshmitm.utils import resources

CONFIGFILE = ConfigParser()

# read default config
conf = resources.files("sshmitm") / "data/default.ini"
CONFIGFILE.read_string(conf.read_text())

configfile_path_list = [
    "/etc/ssh-mitm.ini",
    "/etc/sshmitm.ini",
    os.path.expanduser("~/ssh-mitm.ini"),
    os.path.expanduser("~/sshmitm.ini"),
]

# check if a production or user config exists and read it
for configpath in configfile_path_list:
    if os.path.isfile(configpath):
        CONFIGFILE.read(configpath)
        break

sshmitm_config_env = os.environ.get("SSHMITM_CONFIG")
if sshmitm_config_env and os.path.isfile(sshmitm_config_env):
    CONFIGFILE.read(sshmitm_config_env)
