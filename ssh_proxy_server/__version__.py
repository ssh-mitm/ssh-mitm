import logging
import requests
from packaging import version as p_version

version = '0.5.13'


def check_version():
    try:
        response = requests.get("https://api.github.com/repos/ssh-mitm/ssh-mitm/releases/latest")
        latest_version = response.json()["tag_name"]
        if p_version.parse(version) < p_version.parse(latest_version):
            return latest_version
    except Exception:
        logging.debug("version check failed")
    return None
