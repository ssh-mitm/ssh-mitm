"""
Project-wide constants and default configuration locations for the SSH-MITM project.

This module provides names, URLs, file paths and environment variable names that
are used across the application. Keep this module lightweight — it should only
contain immutable configuration constants, not runtime logic.

:note: Paths in ``CONFIGFILE_PATH_LIST`` are searched in order when loading a
       configuration file. The environment variable specified by
       ``CONFIG_ENV_VAR_NAME`` can be used to override the default config file.
"""

import os

# Basic project metadata
PROJECT_NAME = "SSH-MITM"
PROJECT_SLOGAN = "ssh audits made simple"

# Public documentation and issue tracker
PROJECT_DOCUMENTATION_URL = "https://docs.ssh-mitm.at"
PROJECT_ISSUES_URL = "https://github.com/ssh-mitm/ssh-mitm/issues"

# Command names and packaging identifiers
# - COMMAND_NAME: main CLI command installed for the project
# - COMMAND_NAME_FLATPAK: Flatpak application identifier (if packaging as Flatpak)
COMMAND_NAME = "ssh-mitm"
COMMAND_NAME_FLATPAK = "at.ssh_mitm.server"

# Python module name and default paths inside the project package
MODULE_NAME = "sshmitm"
MODULE_CONFIG_PATH = "data/default.ini"
MODULE_VULNDB_PATH = "data/client_info.yml"

# Default locations to search for a user/system configuration file.
# These paths are searched in order; the first readable file found is used.
CONFIGFILE_PATH_LIST = [
    "/etc/ssh-mitm.ini",
    "/etc/sshmitm.ini",
    os.path.expanduser("~/ssh-mitm.ini"),
    os.path.expanduser("~/sshmitm.ini"),
]

# Environment variable name that may point to an alternate configuration file.
# If set, the application should prefer the file path given by this environment
# variable over the default search list.
CONFIG_ENV_VAR_NAME = "SSHMITM_CONFIG"
