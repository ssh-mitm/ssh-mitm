import re
import logging
from collections import defaultdict
from typing import (
    cast,
    TYPE_CHECKING,
    List,
    Optional,
    Dict,
    Union,
    Any,
    DefaultDict
)

from colored.colored import attr, stylize, fg  # type: ignore
from packaging import version

from paramiko import ECDSAKey
from rich._emoji_codes import EMOJI

import sshmitm
from sshmitm.plugins.session.server_host_key_algorithms import SERVER_HOST_KEY_ALGORITHMS

if TYPE_CHECKING:
    from sshmitm.plugins.session.key_negotiation import KeyNegotiationData


class Vulnerability:

    def __init__(self, cve: str, indocs: bool = False) -> None:
        self.cve: str = cve
        self.indocs: bool = indocs

    @property
    def url(self) -> str:
        if self.indocs:
            return f"https://docs.ssh-mitm.at/vulnerabilities/{self.cve}.html"
        return f"https://nvd.nist.gov/vuln/detail/{self.cve}"


class SSHClientAudit():

    def __init__(
        self,
        key_negotiation_data: 'sshmitm.plugins.session.key_negotiation.KeyNegotiationData',
        client_version: str,
        client_name: Optional[str] = None,
        client_info: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> None:
        self.key_negotiation_data: 'KeyNegotiationData' = key_negotiation_data
        self.client_name: Optional[str] = client_name
        self.client_version: str = client_version
        self.client_info: Dict[str, Dict[str, Any]] = client_info or {}
        self.product_name: Optional[str] = cast(str, self.client_info.get('name', ""))
        self.vendor_url: Optional[str] = cast(str, self.client_info.get('url', ""))

    def get_version_string(self) -> Optional[str]:
        for version_regex in self.client_info.get('version_regex', []):
            version_sring = re.match(version_regex, self.key_negotiation_data.client_version.lower())
            if version_sring:
                return version_sring[1]
        return None

    def between_versions(self, version_min: Union[None, int, float, str], version_max: Union[None, int, float, str]) -> bool:
        try:
            version_string = self.get_version_string()
            if not version_string:
                return False
            if version_min is None and version_max is None:
                return True
            if version_min is None and version_max is not None:
                return version.parse(version_string) <= version.parse(str(version_max))
            if version_min is not None and version_max is None:
                return version.parse(str(version_min)) <= version.parse(version_string)
            return version.parse(str(version_min)) <= version.parse(version_string) <= version.parse(str(version_max))
        except ValueError:
            return False

    def check_cves(self, vulnerabilities: Dict[str, List[str]]) -> List[str]:
        cvelist: Dict[str, Vulnerability] = {}
        for cve, description in self.client_info.get('vulnerabilities', {}).items():
            version_min = description.get('version_min', "")
            version_max = description.get('version_max', "")
            indocs = description.get('docs', False)
            if self.between_versions(version_min, version_max):
                cvelist[cve] = Vulnerability(cve, indocs)

        cvemessagelist: List[str] = []
        if cvelist:
            for e in cvelist.values():
                cvemessagelist.append(f"  * {e.cve}: {e.url}")
                if e.cve in vulnerabilities.keys():
                    if isinstance(vulnerabilities[e.cve], list):
                        for e1 in vulnerabilities[e.cve]:
                            cvemessagelist.append(f"    - {e1}")
                    else:
                        cvemessagelist.append("\n".join([f"    - {v}" for v in vulnerabilities[e.cve]]))
        return cvemessagelist

    def _find_known_server_host_key_algos(self) -> List[str]:
        messages: List[str] = []
        for client_name, server_host_key_algorithms_list in SERVER_HOST_KEY_ALGORITHMS.items():
            if not isinstance(server_host_key_algorithms_list, list):
                continue
            for host_key_algo in server_host_key_algorithms_list:
                if self.key_negotiation_data.server_host_key_algorithms == host_key_algo:
                    messages.append(
                        f"client uses same server_host_key_algorithms as {client_name}"
                    )
                    messages.append(stylize(
                        "client seems to connect for the first time or using a default key order",
                        fg('green')
                    ))
                    break
        if not messages:
            messages.extend([
                "client does not use a known server_host_key_algorithms list",
                f"offered algorithms: {self.key_negotiation_data.server_host_key_algorithms}"
            ])
        return messages

    def _check_known_clients(self, client_name: str) -> List[str]:
        messages: List[str] = []
        if client_name not in SERVER_HOST_KEY_ALGORITHMS:
            return self._find_known_server_host_key_algos()
        server_host_key_algorithms = SERVER_HOST_KEY_ALGORITHMS.get(client_name)
        if server_host_key_algorithms is None:
            messages.append("client uses same server_host_key_algorithms list for unknown and known hosts")
            return messages
        if isinstance(server_host_key_algorithms, str):
            return self._check_known_clients(server_host_key_algorithms)
        for host_key_algo in server_host_key_algorithms:
            if self.key_negotiation_data.server_host_key_algorithms == host_key_algo:
                messages.append(stylize(
                    "client connecting for the first time or using default key order!",
                    fg('green')
                ))
                break
        else:
            messages.append(stylize(
                "client has a locally cached remote fingerprint.",
                fg('yellow')
            ))
        return messages

    def check_key_negotiation(self) -> Dict[str, List[str]]:
        if isinstance(self.key_negotiation_data.session.proxyserver.host_key, ECDSAKey):
            logging.warning("%s: ecdsa-sha2 key is a bad choice; this will produce false positives!", self.client_info.get('name', ''))

        messages: List[str] = []
        if self.client_name is None or self.client_name not in SERVER_HOST_KEY_ALGORITHMS:
            messages.extend(self._find_known_server_host_key_algos())
        else:
            messages.extend(self._check_known_clients(self.client_name))
        messages.append(
            f"Preferred server host key algorithm: {self.key_negotiation_data.server_host_key_algorithms[0]}"
        )
        return {'clientaudit': messages}

    def run_audit(self) -> None:
        vulnerabilities: DefaultDict[str, List[str]] = defaultdict(list)
        for k, v in self.check_key_negotiation().items():
            vulnerabilities[k].extend(v)

        vulnerabilities["clientaudit"].extend(self.audit())

        log_output = []
        log_output.extend([
            stylize(EMOJI['information'] + " client information:", fg('blue') + attr('bold')),
            f"  - client version: {stylize(self.client_version, fg('green') + attr('bold'))}",
            f"  - product name: {self.product_name}",
            f"  - vendor url:  {self.vendor_url}"
        ])

        cvemessagelist = self.check_cves(vulnerabilities)
        if cvemessagelist:
            log_output.append(
                "".join([
                    stylize(EMOJI['warning'] + " client affected by CVEs:\n", fg('yellow') + attr('bold')),
                    "\n".join(cvemessagelist)
                ])
            )

        client_audits = vulnerabilities.get("clientaudit", [])
        if client_audits:
            log_output.append(
                "".join([
                    stylize(EMOJI['warning'] + " client audit tests:\n", fg('blue') + attr('bold')),
                    "\n".join([f"  * {v}" for v in client_audits])
                ])
            )
        logging.info("%s", "\n".join(log_output))

    def audit(self) -> List[str]:
        return []
