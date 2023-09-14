from configparser import ConfigParser
import os
import pkg_resources


CONFIGFILE = ConfigParser()

# read default config
CONFIGFILE.read(pkg_resources.resource_filename('sshmitm', 'data/default.ini'))

configfile_path_list = [
    '/etc/ssh-mitm.ini',
    '/etc/sshmitm.ini',
    os.path.expanduser('~/ssh-mitm.ini'),
    os.path.expanduser('~/sshmitm.ini')
]

# check if a production or user config exists and read it
for configpath in configfile_path_list:
    if os.path.isfile(configpath):
        CONFIGFILE.read(configpath)
        break

sshmitm_config_env = os.environ.get('SSHMITM_CONFIG')
if sshmitm_config_env and os.path.isfile(sshmitm_config_env):
    CONFIGFILE.read(sshmitm_config_env)
