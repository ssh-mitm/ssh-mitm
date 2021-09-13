import logging
import requests
from packaging import version as p_version
from ssh_proxy_server.__version__ import version as ssh_mitm_version


def check_version():
    try:
        response = requests.get("https://api.github.com/repos/ssh-mitm/ssh-mitm/releases/latest")
        latest_version = response.json()["tag_name"]
        if p_version.parse(ssh_mitm_version) < p_version.parse(latest_version):
            return latest_version
    except Exception:
        logging.debug("version check failed")
    return None
