import logging

from typing import Optional, cast

import requests
from packaging import version as p_version
from typeguard import typechecked
from sshmitm.__version__ import version as ssh_mitm_version


@typechecked
def check_version() -> Optional[str]:
    try:
        response = requests.get("https://api.github.com/repos/ssh-mitm/ssh-mitm/releases/latest")
        latest_version: str = cast(str, response.json()["tag_name"])
        if p_version.parse(ssh_mitm_version) < p_version.parse(latest_version):
            return latest_version
    except Exception:
        logging.debug("version check failed")
    return None
