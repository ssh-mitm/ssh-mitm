import re
import logging
from colored.colored import attr, stylize, fg
from packaging import version

from paramiko import ECDSAKey
from rich._emoji_codes import EMOJI

from ssh_proxy_server.plugins.session import cve202014002, cve202014145


class SSHClientAudit():

    CLIENT_NAME = None
    VERSION_REGEX = None
    server_host_key_algorithms = None
    SERVER_HOST_KEY_ALGORITHMS = None

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

    def check_cves(self):
        found_cves = []
        for cve, description in self.vulnerability_list.items():
            version_min = description.get('version_min', "")
            version_max = description.get('version_max', "")
            ssh_mitm_docs = description.get('docs', False)
            if self.between_versions(version_min, version_max):
                found_cves.append((cve, ssh_mitm_docs))

        if found_cves:
            cvelist = []
            for cve in found_cves:
                if cve[1]:
                    cvelist.append("    {0}: https://docs.ssh.mitm.at/{0}.html".format(cve[0]))
                else:
                    cvelist.append("    {0}: https://nvd.nist.gov/vuln/detail/{0}".format(cve[0]))
            logging.info(
                    "".join([
                        stylize(EMOJI['warning'] + " possible vulnerabilities found!\n", fg('yellow') + attr('bold')),
                        "\n".join(cvelist), fg('yellow')
                    ])
            )

    def check_key_negotiation(self):
        if not self.SERVER_HOST_KEY_ALGORITHMS:
            return
        if isinstance(self.key_negotiation_data.session.proxyserver.host_key, ECDSAKey):
            logging.warning("%s: ecdsa-sha2 key is a bad choice; this will produce false positives!", self.client_name())
        for host_key_algo in self.SERVER_HOST_KEY_ALGORITHMS:
            if self.key_negotiation_data.server_host_key_algorithms == host_key_algo:
                logging.info("[green]%s: Client connecting for the first time or using default key order![/green]", self.client_name(), extra={"markup": True})
                break
        else:
            logging.info("[yellow]%s: Client has a locally cached remote fingerprint!", self.client_name(), extra={"markup": True})

    def audit(self):
        pass


class PuTTY_Release(SSHClientAudit):
    VERSION_REGEX = r'ssh-2.0-putty_release_(0\.[0-9]+)'
    SERVER_HOST_KEY_ALGORITHMS = cve202014002.SERVER_HOST_KEY_ALGORITHMS


class PuTTYFileZilla(SSHClientAudit):
    VERSION_REGEX = r'ssh-2.0-puttyfilezilla_([0-9]+\.[0-9]+\.[0-9]+)'
    SERVER_HOST_KEY_ALGORITHMS = cve202014002.SERVER_HOST_KEY_ALGORITHMS


class WinSCP(SSHClientAudit):
    VERSION_REGEX = r'ssh-2.0-winscp_release_([0-9]+\.[0-9]+\.[0-9]+)'
    SERVER_HOST_KEY_ALGORITHMS = cve202014145.SERVER_HOST_KEY_ALGORITHMS


class OpenSSH(SSHClientAudit):
    VERSION_REGEX = r'ssh-2.0-openssh_([0-9]+\.[0-9]+)p?.*'
    SERVER_HOST_KEY_ALGORITHMS = cve202014145.SERVER_HOST_KEY_ALGORITHMS


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
