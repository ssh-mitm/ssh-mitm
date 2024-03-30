import logging
import re
from collections import defaultdict
from typing import TYPE_CHECKING, Any, DefaultDict, Dict, List, Optional, Union, cast

from colored.colored import attr, fg  # type: ignore[import-untyped]
from packaging import version
from paramiko import ECDSAKey

from sshmitm.logging import Colors
from sshmitm.plugins.session.server_host_key_algorithms import (
    SERVER_HOST_KEY_ALGORITHMS,
)

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.plugins.session.key_negotiation import KeyNegotiationData


class Vulnerability:
    """
    This class represents a vulnerability and holds information about it.

    :param cve: the identifier of the vulnerability (e.g. 'CVE-2022-0001')
    :param indocs: if True, the URL of the vulnerability information will point to the internal docs.
                  if False, the URL will point to the official NIST National Vulnerability Database.
    """

    def __init__(self, cve: str, indocs: bool = False) -> None:
        self.cve: str = cve
        self.indocs: bool = indocs

    @property
    def url(self) -> str:
        """
        Get the URL where the information about the vulnerability can be found.

        :return: the URL
        """
        if self.indocs:
            return f"https://docs.ssh-mitm.at/vulnerabilities/{self.cve}.html"
        return f"https://nvd.nist.gov/vuln/detail/{self.cve}"


class ClientAuditReport:
    def __init__(
        self,
        title: str,
        *,
        vulnerable: bool = False,
        messages: Optional[List[str]] = None,
    ) -> None:
        self.title = title
        self.messages = messages or []
        self.vulnerable = vulnerable

    def __str__(self) -> str:
        title_color = "red" if self.vulnerable else "green"
        value = [f"    {Colors.stylize(self.title, fg(title_color) + attr('bold'))}"]
        value.extend([f"      * {v}" for v in self.messages])
        return "\n".join(value)


class SSHClientAudit:
    """
    The class SSHClientAudit is used for auditing SSH clients.

    :param key_negotiation_data: object of 'sshmitm.plugins.session.key_negotiation.KeyNegotiationData'
    :param client_version: client version string
    :param client_name: optional client name
    :param client_info: optional client information, stored as a dictionary
    """

    def __init__(
        self,
        key_negotiation_data: "sshmitm.plugins.session.key_negotiation.KeyNegotiationData",
        client_version: str,
        client_name: Optional[str] = None,
        client_info: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.key_negotiation_data: "KeyNegotiationData" = key_negotiation_data
        self.client_name: Optional[str] = client_name
        self.client_version: str = client_version
        self.client_info: Dict[str, Dict[str, Any]] = client_info or {}
        self.product_name: Optional[str] = cast(str, self.client_info.get("name", ""))
        self.vendor_url: Optional[str] = cast(str, self.client_info.get("url", ""))

    def get_version_string(self) -> Optional[str]:
        """
        This method returns version string extracted from the `client_version` string in the `key_negotiation_data` object
        using the `version_regex` field of `client_info` dictionary.

        :return: version string
        """
        for version_regex in self.client_info.get("version_regex", []):
            version_sring = re.match(
                version_regex, self.key_negotiation_data.client_version.lower()
            )
            if version_sring:
                return version_sring[1]
        return None

    def between_versions(
        self,
        version_min: Union[None, float, str],
        version_max: Union[None, float, str],
    ) -> bool:
        """
        This method returns `True` if the version string is between `version_min` and `version_max`.
        Returns `False` otherwise.

        :param version_min: minimum version number
        :param version_max: maximum version number
        :return: `True` if version string is between `version_min` and `version_max`, `False` otherwise
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
            return (
                version.parse(str(version_min))
                <= version.parse(version_string)
                <= version.parse(str(version_max))
            )
        except ValueError:
            return False

    def check_cves(
        self, vulnerabilities: DefaultDict[str, List[Optional[ClientAuditReport]]]
    ) -> List[str]:
        """
        This method returns a list of strings representing the Common Vulnerabilities and Exposures (CVEs) found in the client,
        along with the information available in the `vulnerabilities` dictionary.

        :param vulnerabilities: dictionary of CVEs and their descriptions
        :return: list of strings representing the CVEs and their information
        """
        cvelist: Dict[str, Vulnerability] = {}
        for cve, description in self.client_info.get("vulnerabilities", {}).items():
            version_min = description.get("version_min", "")
            version_max = description.get("version_max", "")
            indocs = description.get("docs", False)
            if self.between_versions(version_min, version_max):
                cvelist[cve] = Vulnerability(cve, indocs)

        cvemessagelist: List[str] = []
        if cvelist:
            for cve_entry in cvelist.values():
                cvemessagelist.append(f"  * {cve_entry.cve}: {cve_entry.url}")
                if cve_entry.cve in vulnerabilities:
                    if isinstance(vulnerabilities[cve_entry.cve], list):
                        for vulnerability_entry in vulnerabilities[cve_entry.cve]:
                            cvemessagelist.append(  # noqa: PERF401
                                f"    - {vulnerability_entry}"
                            )
                    else:
                        cvemessagelist.append(
                            "\n".join(
                                [
                                    f"    - {vulnerability}"
                                    for vulnerability in vulnerabilities[cve_entry.cve]
                                ]
                            )
                        )
        return cvemessagelist

    def _find_known_server_host_key_algos(self) -> List[str]:
        """
        This method returns a list of strings representing the server host key algorithms known to the client.

        :return: list of strings representing server host key algorithms
        """
        messages: List[str] = []
        for (
            client_name,
            server_host_key_algorithms_list,
        ) in SERVER_HOST_KEY_ALGORITHMS.items():
            if not isinstance(server_host_key_algorithms_list, list):
                continue
            for host_key_algo in server_host_key_algorithms_list:
                if (
                    self.key_negotiation_data.server_host_key_algorithms
                    == host_key_algo
                ):
                    messages.append(
                        f"client uses same server_host_key_algorithms as {client_name}"
                    )
                    messages.append(
                        Colors.stylize(
                            "client seems to connect for the first time or using a default key order",
                            fg("green"),
                        )
                    )
                    break
        if not messages:
            messages.extend(
                [
                    "client does not use a known server_host_key_algorithms list",
                    f"offered algorithms: {self.key_negotiation_data.server_host_key_algorithms}",
                ]
            )
        return messages

    def _check_known_clients(self, client_name: str) -> List[str]:
        """
        Check if a client with the given ID is already registered as a known client.

        :param client_id: ID of the client to check
        :return: True if the client is known, False otherwise
        """
        messages: List[str] = []
        if client_name not in SERVER_HOST_KEY_ALGORITHMS:
            return self._find_known_server_host_key_algos()
        server_host_key_algorithms = SERVER_HOST_KEY_ALGORITHMS.get(client_name)
        if server_host_key_algorithms is None:
            messages.append(
                "client uses same server_host_key_algorithms list for unknown and known hosts"
            )
            return messages
        if isinstance(server_host_key_algorithms, str):
            return self._check_known_clients(server_host_key_algorithms)
        for host_key_algo in server_host_key_algorithms:
            if self.key_negotiation_data.server_host_key_algorithms == host_key_algo:
                messages.append(
                    Colors.stylize(
                        "client connecting for the first time or using default key order!",
                        fg("green"),
                    )
                )
                break
        else:
            messages.append(
                Colors.stylize(
                    "client has a locally cached remote fingerprint.", fg("yellow")
                )
            )
        return messages

    def check_key_negotiation(self) -> Dict[str, ClientAuditReport]:
        """
        Check if a key negotiation data is known.
        """
        if isinstance(self.key_negotiation_data.session.proxyserver.host_key, ECDSAKey):
            logging.warning(
                "%s: ecdsa-sha2 key is a bad choice; this will produce false positives!",
                self.client_info.get("name", ""),
            )

        messages: List[str] = []
        if (
            self.client_name is None
            or self.client_name not in SERVER_HOST_KEY_ALGORITHMS
        ):
            messages.extend(self._find_known_server_host_key_algos())
        else:
            messages.extend(self._check_known_clients(self.client_name))
        messages.append(
            f"Preferred server host key algorithm: {self.key_negotiation_data.server_host_key_algorithms[0]}"
        )
        report = ClientAuditReport(
            "CVE-2020-14145 - Fingerprint information leak",
            vulnerable=False,
            messages=messages,
        )
        return {"clientaudit": report}

    def check_terrapin_attack(self) -> Dict[str, ClientAuditReport]:
        cha_cha20 = "chacha20-poly1305@openssh.com"
        etm_suffix = "-etm@openssh.com"
        cbc_suffix = "-cbc"
        kex_strict_indicator_client = "kex-strict-c-v00@openssh.com"
        # kex_strict_indicator_server = "kex-strict-s-v00@openssh.com"  # noqa: ERA001

        supports_cha_cha20 = (
            cha_cha20
            in self.key_negotiation_data.encryption_algorithms_client_to_server
            or cha_cha20
            in self.key_negotiation_data.encryption_algorithms_server_to_client
        )
        supports_cbc_etm = (
            any(
                algo.endswith(cbc_suffix)
                for algo in self.key_negotiation_data.encryption_algorithms_client_to_server
            )
            and any(
                mac.endswith(etm_suffix)
                for mac in self.key_negotiation_data.mac_algorithms_client_to_server
            )
        ) or (
            any(
                algo.endswith(cbc_suffix)
                for algo in self.key_negotiation_data.encryption_algorithms_server_to_client
            )
            and any(
                mac.endswith(etm_suffix)
                for mac in self.key_negotiation_data.mac_algorithms_server_to_client
            )
        )
        supports_strict_kex = (
            kex_strict_indicator_client in self.key_negotiation_data.kex_algorithms
        )
        vulnerable = (supports_cbc_etm or supports_cbc_etm) and not supports_strict_kex
        title_color = "red" if vulnerable else "green"

        report = ClientAuditReport(
            "CVE-2023-48795 - Terrapin-Attack", vulnerable=vulnerable
        )
        report.messages.append(f"ChaCha20-Poly1305 support:   {supports_cha_cha20}")
        report.messages.append(f"CBC-EtM support:             {supports_cbc_etm}")
        report.messages.append(f"Strict key exchange support: {supports_strict_kex}")
        report.messages.append(
            f"Mitigation status:           {Colors.stylize('vulnerable' if vulnerable else 'mitigated', fg(title_color))}"
        )
        return {"clientaudit": report}

    def run_audit(self) -> None:
        """
        Run an audit on the client with the given ID.
        """
        vulnerabilities: DefaultDict[str, List[Optional[ClientAuditReport]]] = (
            defaultdict(list)
        )
        for audit_type, audit_results in self.check_key_negotiation().items():
            vulnerabilities[audit_type].append(audit_results)
        for audit_type, audit_results in self.check_terrapin_attack().items():
            vulnerabilities[audit_type].append(audit_results)

        vulnerabilities["clientaudit"].append(self.audit())

        log_output = []
        log_output.extend(
            [
                Colors.stylize(
                    Colors.emoji("information") + " client information:",
                    fg("blue") + attr("bold"),
                ),
                f"  - client version: {Colors.stylize(self.client_version, fg('green') + attr('bold'))}",
                f"  - product name: {self.product_name}",
                f"  - vendor url:  {self.vendor_url}",
                f" - client address: ip={self.key_negotiation_data.session.client_address[0]} port={self.key_negotiation_data.session.client_address[1]}",
            ]
        )

        cvemessagelist = self.check_cves(vulnerabilities)
        if cvemessagelist:
            log_output.append(
                "".join(
                    [
                        Colors.stylize(
                            Colors.emoji("warning")
                            + " CVEs detected by client version string:\n",
                            fg("yellow") + attr("bold"),
                        ),
                        "\n".join(cvemessagelist),
                    ]
                )
            )

        client_audits = vulnerabilities.get("clientaudit", [])
        if client_audits:
            log_output.append(
                "".join(
                    [
                        Colors.stylize(
                            Colors.emoji("warning")
                            + " detected vulnerabilities by active tests:\n",
                            fg("blue") + attr("bold"),
                        ),
                        "\n".join([str(v) for v in client_audits if v]),
                    ]
                )
            )
        logging.info(
            "%s",
            "\n".join(log_output),
            extra={
                "client_version": self.client_version,
                "product_name": self.product_name,
                "vendor_url": self.vendor_url,
                "client_address": {
                    "ip": self.key_negotiation_data.session.client_address[0],
                    "port": self.key_negotiation_data.session.client_address[1],
                },
            },
        )

    def audit(self) -> Optional[ClientAuditReport]:
        """
        Run audits on all clients.
        """
        return None
