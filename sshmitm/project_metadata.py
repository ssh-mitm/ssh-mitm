import os

PROJECT_NAME = "SSH-MITM"
PROJECT_SLOGAN = "ssh audits made simple"
PROJECT_DOCUMENTATION_URL = "https://docs.ssh-mitm.at"
PROJECT_ISSUES_URL = "https://github.com/ssh-mitm/ssh-mitm/issues"

COMMAND_NAME = "ssh-mitm"
COMMAND_NAME_FLATPAK = "at.ssh_mitm.server"

MODULE_NAME = "sshmitm"
MODULE_CONFIG_PATH = "data/default.ini"
MODULE_VULNDB_PATH = "data/client_info.yml"

CONFIGFILE_PATH_LIST = [
    "/etc/ssh-mitm.ini",
    "/etc/sshmitm.ini",
    os.path.expanduser("~/ssh-mitm.ini"),
    os.path.expanduser("~/sshmitm.ini"),
]
CONFIG_ENV_VAR_NAME = "SSHMITM_CONFIG"
