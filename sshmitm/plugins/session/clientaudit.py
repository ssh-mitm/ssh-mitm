import re
import logging
from collections import defaultdict
from typing import (
    cast,
    TYPE_CHECKING,
    Text,
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
from sshmitm.plugins.session import cve202014002, cve202014145

if TYPE_CHECKING:
    from sshmitm.plugins.session.key_negotiation import KeyNegotiationData


class Vulnerability:

    def __init__(self, cve: Text, indocs: bool = False) -> None:
        self.cve: Text = cve
        self.indocs: bool = indocs

    @property
    def url(self) -> Text:
        if self.indocs:
            return f"https://docs.ssh-mitm.at/vulnerabilities/{self.cve}.html"
        return f"https://nvd.nist.gov/vuln/detail/{self.cve}"


class SSHClientAudit():

    SERVER_HOST_KEY_ALGORITHMS: Optional[List[List[Text]]] = None
    SERVER_HOST_KEY_ALGORITHMS_CVE: Optional[Text] = None

    def __init__(
        self,
        key_negotiation_data: 'sshmitm.plugins.session.key_negotiation.KeyNegotiationData',
        client_version: Text,
        client_info: Dict[Text, Dict[Text, Any]]
    ) -> None:
        self.key_negotiation_data: 'KeyNegotiationData' = key_negotiation_data
        self.client_version: Text = client_version
        self.client_info: Dict[Text, Dict[Text, Any]] = client_info
        self.product_name: Optional[Text] = cast(str, self.client_info.get('name', ""))
        self.vendor_url: Optional[Text] = cast(str, self.client_info.get('url', ""))

    def get_version_string(self) -> Optional[Text]:
        version_regex = self.client_info.get('version_regex', None)
        if not version_regex:
            return None
        version_sring = re.match(version_regex, self.key_negotiation_data.client_version.lower())
        if version_sring:
            return version_sring[1]
        return None

    def between_versions(self, version_min: Union[None, int, float, Text], version_max: Union[None, int, float, Text]) -> bool:
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

    def check_cves(self, vulnerabilities: Dict[Text, List[Text]]) -> List[Text]:
        cvelist: Dict[Text, Vulnerability] = {}
        for cve, description in self.client_info.get('vulnerabilities', {}).items():
            version_min = description.get('version_min', "")
            version_max = description.get('version_max', "")
            indocs = description.get('docs', False)
            if self.between_versions(version_min, version_max):
                cvelist[cve] = Vulnerability(cve, indocs)

        cvemessagelist: List[Text] = []
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

    def check_key_negotiation(self) -> Dict[Text, List[Text]]:
        messages: List[Text] = []
        if not self.SERVER_HOST_KEY_ALGORITHMS or not self.SERVER_HOST_KEY_ALGORITHMS_CVE:
            return {}
        if isinstance(self.key_negotiation_data.session.proxyserver.host_key, ECDSAKey):
            logging.warning("%s: ecdsa-sha2 key is a bad choice; this will produce false positives!", self.client_info.get('name', ''))
        for host_key_algo in self.SERVER_HOST_KEY_ALGORITHMS or []:
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
        messages.append(
            f"Preferred server host key algorithm: {self.key_negotiation_data.server_host_key_algorithms[0]}"
        )
        return {self.SERVER_HOST_KEY_ALGORITHMS_CVE: messages}

    def run_audit(self) -> None:
        vulnerabilities: DefaultDict[Text, List[Text]] = defaultdict(list)
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
                    stylize(EMOJI['warning'] + " client audit tests:\n", fg('yellow') + attr('bold')),
                    "\n".join([f"  * {v}" for v in client_audits])
                ])
            )
        logging.info("%s", "\n".join(log_output))

    def audit(self) -> List[Text]:
        return []


class PuTTY_Release(SSHClientAudit):
    SERVER_HOST_KEY_ALGORITHMS = cve202014002.SERVER_HOST_KEY_ALGORITHMS
    SERVER_HOST_KEY_ALGORITHMS_CVE = cve202014002.CVE


class OpenSSH(SSHClientAudit):
    SERVER_HOST_KEY_ALGORITHMS = cve202014145.SERVER_HOST_KEY_ALGORITHMS
    SERVER_HOST_KEY_ALGORITHMS_CVE = cve202014145.CVE


class AsyncSSH(SSHClientAudit):
    SERVER_HOST_KEY_ALGORITHMS = [
        [  # asyncssh 2.7.0
            'sk-ssh-ed25519-cert-v01@openssh.com', 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ssh-ed25519-cert-v01@openssh.com', 'ssh-ed448-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
            'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-1.3.132.0.10-cert-v01@openssh.com',
            'ssh-rsa-cert-v01@openssh.com', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com',
            'ssh-ed25519', 'ssh-ed448', 'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256',
            'ecdsa-sha2-1.3.132.0.10', 'rsa-sha2-256', 'rsa-sha2-512', 'ssh-rsa-sha224@ssh.com', 'ssh-rsa-sha256@ssh.com',
            'ssh-rsa-sha384@ssh.com', 'ssh-rsa-sha512@ssh.com', 'ssh-rsa'
        ]
    ]


class RubyNetSsh(SSHClientAudit):
    SERVER_HOST_KEY_ALGORITHMS = [
        [  # ruby/net::ssh_5.2.0 x86_64-linux-gnu
            'ssh-ed25519-cert-v01@openssh.com', 'ssh-ed25519', 'ecdsa-sha2-nistp521-cert-v01@openssh.com',
            'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256', 'ssh-rsa-cert-v01@openssh.com',
            'ssh-rsa-cert-v00@openssh.com', 'ssh-rsa', 'ssh-dss'
        ]
    ]


class MoTTY_Release(SSHClientAudit):
    """MobaXterm ssh client implementation"""
    SERVER_HOST_KEY_ALGORITHMS_CVE: Optional[Text] = 'CVE-2020-14002'
    SERVER_HOST_KEY_ALGORITHMS = [
        [
            'ssh-ed448', 'ssh-ed25519',
            'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521', 'rsa-sha2-512',
            'rsa-sha2-256', 'ssh-rsa', 'ssh-dss'
        ]
    ]
