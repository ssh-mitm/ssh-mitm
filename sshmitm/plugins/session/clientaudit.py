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
    """
    This class represents a vulnerability and holds information about it.

    :param cve: the identifier of the vulnerability (e.g. 'CVE-2022-0001')
    :type cve: str
    :param indocs: if True, the URL of the vulnerability information will point to the internal docs.
                  if False, the URL will point to the official NIST National Vulnerability Database.
    :type indocs: bool
    """

    def __init__(self, cve: str, indocs: bool = False) -> None:
        self.cve: str = cve
        self.indocs: bool = indocs

    @property
    def url(self) -> str:
        """
        Get the URL where the information about the vulnerability can be found.

        :return: the URL
        :rtype: str
        """
        if self.indocs:
            return f"https://docs.ssh-mitm.at/vulnerabilities/{self.cve}.html"
        return f"https://nvd.nist.gov/vuln/detail/{self.cve}"


class SSHClientAudit():
    """
    The class SSHClientAudit is used for auditing SSH clients.

    :param key_negotiation_data: object of 'sshmitm.plugins.session.key_negotiation.KeyNegotiationData'
    :type key_negotiation_data: 'sshmitm.plugins.session.key_negotiation.KeyNegotiationData'
    :param client_version: client version string
    :type client_version: str
    :param client_name: optional client name
    :type client_name: Optional[str]
    :param client_info: optional client information, stored as a dictionary
    :type client_info: Optional[Dict[str, Dict[str, Any]]]
    :return: None
    :rtype: None
    """

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
        """
        This method returns version string extracted from the `client_version` string in the `key_negotiation_data` object
        using the `version_regex` field of `client_info` dictionary.

        :return: version string
        :rtype: Optional[str]
        """
        for version_regex in self.client_info.get('version_regex', []):
            version_sring = re.match(version_regex, self.key_negotiation_data.client_version.lower())
            if version_sring:
                return version_sring[1]
        return None

    def between_versions(self, version_min: Union[None, int, float, str], version_max: Union[None, int, float, str]) -> bool:
        """
        This method returns `True` if the version string is between `version_min` and `version_max`.
        Returns `False` otherwise.

        :param version_min: minimum version number
        :type version_min: Union[None, int, float, str]
        :param version_max: maximum version number
        :type version_max: Union[None, int, float, str]
        :return: `True` if version string is between `version_min` and `version_max`, `False` otherwise
        :rtype: bool
        """
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
        """
        This method returns a list of strings representing the Common Vulnerabilities and Exposures (CVEs) found in the client,
        along with the information available in the `vulnerabilities` dictionary.

        :param vulnerabilities: dictionary of CVEs and their descriptions
        :type vulnerabilities: Dict[str, List[str]]
        :return: list of strings representing the CVEs and their information
        :rtype: List[str]
        """
        cvelist: Dict[str, Vulnerability] = {}
        for cve, description in self.client_info.get('vulnerabilities', {}).items():
            version_min = description.get('version_min', "")
            version_max = description.get('version_max', "")
            indocs = description.get('docs', False)
            if self.between_versions(version_min, version_max):
                cvelist[cve] = Vulnerability(cve, indocs)

        cvemessagelist: List[str] = []
        if cvelist:
            for cve_entry in cvelist.values():
                cvemessagelist.append(f"  * {cve_entry.cve}: {cve_entry.url}")
                if cve_entry.cve in vulnerabilities.keys():
                    if isinstance(vulnerabilities[cve_entry.cve], list):
                        for vulnerability_entry in vulnerabilities[cve_entry.cve]:
                            cvemessagelist.append(f"    - {vulnerability_entry}")
                    else:
                        cvemessagelist.append("\n".join([f"    - {vulnerability}" for vulnerability in vulnerabilities[cve_entry.cve]]))
        return cvemessagelist

    def _find_known_server_host_key_algos(self) -> List[str]:
        """
        This method returns a list of strings representing the server host key algorithms known to the client.

        :return: list of strings representing server host key algorithms
        :rtype: List[str]
        """
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
        """
        Check if a client with the given ID is already registered as a known client.

        :param client_id: ID of the client to check
        :type client_id: str
        :return: True if the client is known, False otherwise
        :rtype: bool
        """
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
        """
        Check if a key negotiation data is known.

        :param client_id: ID of the client to check
        :type client_id: str
        :return: True if key negotiation data is known, False otherwise
        :rtype: bool
        """
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
        """
        Run an audit on the client with the given ID.

        :param client_id: ID of the client to audit
        :type client_id: str
        :return: None
        :rtype: None
        """
        vulnerabilities: DefaultDict[str, List[str]] = defaultdict(list)
        for audit_type, audit_results in self.check_key_negotiation().items():
            vulnerabilities[audit_type].extend(audit_results)

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
        """
        Run audits on all clients.

        :return: None
        :rtype: None
        """
        return []
