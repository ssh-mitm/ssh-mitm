import re
import logging
from collections import defaultdict
from colored.colored import attr, stylize, fg  # type: ignore
from packaging import version
from typing import (
    TYPE_CHECKING,
    Text,
    List,
    Optional,
    Dict,
    Union,
    Any,
    DefaultDict
)

from paramiko import ECDSAKey
from rich._emoji_codes import EMOJI
from typeguard import typechecked

import sshmitm
from sshmitm.plugins.session import cve202014002, cve202014145

if TYPE_CHECKING:
    from sshmitm.plugins.session.key_negotiation import KeyNegotiationData


class Vulnerability:

    @typechecked
    def __init__(self, cve: Text, indocs: bool = False) -> None:
        self.cve: Text = cve
        self.indocs: bool = indocs

    @property
    def url(self) -> Text:
        if self.indocs:
            return f"https://docs.ssh.mitm.at/{self.cve}.html"
        return f"https://nvd.nist.gov/vuln/detail/{self.cve}"


class SSHClientAudit():

    CLIENT_NAME: Optional[Text] = None
    VERSION_REGEX: Optional[Text] = None
    SERVER_HOST_KEY_ALGORITHMS: Optional[List[List[Text]]] = None
    SERVER_HOST_KEY_ALGORITHMS_CVE: Optional[Text] = None

    @typechecked
    def __init__(
        self,
        key_negotiation_data: 'sshmitm.plugins.session.key_negotiation.KeyNegotiationData',
        vulnerability_list: Dict[Text, Dict[Text, Any]]
    ) -> None:
        self.key_negotiation_data: 'KeyNegotiationData' = key_negotiation_data
        self.vulnerability_list: Dict[Text, Dict[Text, Any]] = vulnerability_list

    @classmethod
    @typechecked
    def client_name(cls) -> Text:
        return cls.CLIENT_NAME or cls.__name__.lower()

    @typechecked
    def get_version_string(self) -> Optional[Text]:
        if not self.VERSION_REGEX:
            return None
        version_sring = re.match(self.VERSION_REGEX, self.key_negotiation_data.client_version.lower())
        if version_sring:
            return version_sring[1]
        return None

    @typechecked
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

    @typechecked
    def check_cves(self, vulnerabilities: Dict[Text, List[Text]]) -> None:
        cvelist: Dict[Text, Vulnerability] = {}
        for cve, description in self.vulnerability_list.items():
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
        if cvemessagelist or True:
            logging.info(
                    "".join([
                        stylize(EMOJI['warning'] + " client affected by CVEs:\n", fg('yellow') + attr('bold')),
                        "\n".join(cvemessagelist)
                    ])
            )

    @typechecked
    def check_key_negotiation(self) -> Dict[Text, List[Text]]:
        messages: List[Text] = []
        if not self.SERVER_HOST_KEY_ALGORITHMS or not self.SERVER_HOST_KEY_ALGORITHMS_CVE:
            return {}
        if isinstance(self.key_negotiation_data.session.proxyserver.host_key, ECDSAKey):
            logging.warning("%s: ecdsa-sha2 key is a bad choice; this will produce false positives!", self.client_name())
        for host_key_algo in self.SERVER_HOST_KEY_ALGORITHMS:
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

    @typechecked
    def run_audit(self) -> None:
        vulnerabilities: DefaultDict[Text, List[Text]] = defaultdict(list)
        for k, v in self.check_key_negotiation().items():
            vulnerabilities[k].extend(v)

        vulnerabilities["clientaudit"].extend(self.audit())

        self.check_cves(vulnerabilities)
        client_audits = vulnerabilities.get("clientaudit", [])
        if client_audits:
            logging.info(
                "".join([
                    stylize(EMOJI['warning'] + " client audit tests:\n", fg('yellow') + attr('bold')),
                    "\n".join([f"  * {v}" for v in client_audits])
                ])
            )

    @typechecked
    def audit(self) -> List[Text]:
        return []


class PuTTY_Release(SSHClientAudit):
    VERSION_REGEX = r'ssh-2.0-putty_release_(0\.[0-9]+)'
    SERVER_HOST_KEY_ALGORITHMS = cve202014002.SERVER_HOST_KEY_ALGORITHMS
    SERVER_HOST_KEY_ALGORITHMS_CVE = cve202014002.CVE


class PuTTYFileZilla(PuTTY_Release):
    VERSION_REGEX = r'ssh-2.0-puttyfilezilla_([0-9]+\.[0-9]+\.[0-9]+)'


class WinSCP(PuTTY_Release):
    VERSION_REGEX = r'ssh-2.0-winscp_release_([0-9]+\.[0-9]+\.[0-9]+)'


class OpenSSH(SSHClientAudit):
    VERSION_REGEX = r'ssh-2.0-openssh_([0-9]+\.[0-9]+)p?.*'
    SERVER_HOST_KEY_ALGORITHMS = cve202014145.SERVER_HOST_KEY_ALGORITHMS
    SERVER_HOST_KEY_ALGORITHMS_CVE = cve202014145.CVE


class Dropbear(SSHClientAudit):
    VERSION_REGEX = r'ssh-2.0-dropbear_([0-9]+\.[0-9]+)'


class AsyncSSH(SSHClientAudit):
    VERSION_REGEX = r'ssh-2.0-asyncssh_([0-9]+\.[0-9]+\.[0-9]+)'
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
    VERSION_REGEX = r'ssh-2.0-ruby/net::ssh_([0-9]+\.[0-9]+\.[0-9]+)\s+.*'
    SERVER_HOST_KEY_ALGORITHMS = [
        [  # ruby/net::ssh_5.2.0 x86_64-linux-gnu
            'ssh-ed25519-cert-v01@openssh.com', 'ssh-ed25519', 'ecdsa-sha2-nistp521-cert-v01@openssh.com',
            'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256', 'ssh-rsa-cert-v01@openssh.com',
            'ssh-rsa-cert-v00@openssh.com', 'ssh-rsa', 'ssh-dss'
        ]
    ]

    @classmethod
    @typechecked
    def client_name(cls) -> Text:
        return 'ruby/net::ssh'
