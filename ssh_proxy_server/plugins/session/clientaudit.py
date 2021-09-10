import re
import logging
from collections import defaultdict
from colored.colored import attr, stylize, fg
from packaging import version

from paramiko import ECDSAKey
from rich._emoji_codes import EMOJI

from ssh_proxy_server.plugins.session import cve202014002, cve202014145

class Vulnerability:

    def __init__(self, cve, indocs=False) -> None:
        self.cve = cve
        self.indocs = indocs
        self.messages = []

    @property
    def url(self):
        if self.indocs:
            return f"https://docs.ssh.mitm.at/{self.cve}.html"
        return f"https://nvd.nist.gov/vuln/detail/{self.cve}"


class SSHClientAudit():

    CLIENT_NAME = None
    VERSION_REGEX = None
    SERVER_HOST_KEY_ALGORITHMS = None
    SERVER_HOST_KEY_ALGORITHMS_CVE = None

    def __init__(self, key_negotiation_data, vulnerability_list) -> None:
        self.key_negotiation_data = key_negotiation_data
        self.vulnerability_list = vulnerability_list

    @classmethod
    def client_name(cls):
        return cls.CLIENT_NAME or cls.__name__.lower()

    def get_version_string(self):
        if not self.VERSION_REGEX:
            return None
        version_sring = re.match(self.VERSION_REGEX, self.key_negotiation_data.client_version.lower())
        if version_sring:
            return version_sring[1]
        return None

    def between_versions(self, version_min, version_max):
        try:
            version_string = self.get_version_string()
            if not version_string:
                return False
            return version.parse(str(version_min)) <= version.parse(version_string) <= version.parse(str(version_max))
        except ValueError:
            return False

    def check_cves(self, vulnerabilities):
        cvelist = defaultdict(dict)
        for cve, description in self.vulnerability_list.items():
            version_min = description.get('version_min', "")
            version_max = description.get('version_max', "")
            indocs = description.get('docs', False)
            if self.between_versions(version_min, version_max):
                cvelist[cve] = Vulnerability(cve, indocs)


        cvemessagelist = []
        if cvelist:
            for e in cvelist.values():
                cvemessagelist.append(f"  * {e.cve}: {e.url}")
                if e.cve in vulnerabilities.keys():
                    cvemessagelist.append("\n".join([f"    - {v}" for v in vulnerabilities[e.cve]]))

        logging.info(
                "".join([
                    stylize(EMOJI['warning'] + " client affected by CVEs:\n", fg('yellow') + attr('bold')),
                    "\n".join(cvemessagelist)
                ])
        )

    def check_key_negotiation(self):
        if not self.SERVER_HOST_KEY_ALGORITHMS:
            return {}
        if isinstance(self.key_negotiation_data.session.proxyserver.host_key, ECDSAKey):
            logging.warning("%s: ecdsa-sha2 key is a bad choice; this will produce false positives!", self.client_name())
        for host_key_algo in self.SERVER_HOST_KEY_ALGORITHMS:
            if self.key_negotiation_data.server_host_key_algorithms == host_key_algo:
                message = stylize(f"client connecting for the first time or using default key order!", fg('green'))
                break
        else:
            message = stylize(f"client has a locally cached remote fingerprint!", fg('yellow'))
        return {self.SERVER_HOST_KEY_ALGORITHMS_CVE: message}

    def run_audit(self):
        vulnerabilities = defaultdict(list)
        for k, v in self.check_key_negotiation().items():
            if isinstance(v, list):
                vulnerabilities[k].extend(v)
            else:
                vulnerabilities[k].append(v)

        for k, v in self.audit().items():
            if isinstance(v, list):
                vulnerabilities[k].extend(v)
            else:
                vulnerabilities[k].append(v)

        self.check_cves(vulnerabilities)
        client_audits = vulnerabilities.get(None, [])
        if client_audits:
            logging.info(
                "".join([
                    stylize(EMOJI['warning'] + " client audit tests:\n", fg('yellow') + attr('bold')),
                    "\n".join([f"  * {v}" for v in client_audits])
                ])
            )

    def audit(self):
        return {None: []}


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
    def client_name(cls):
        return 'ruby/net::ssh'
