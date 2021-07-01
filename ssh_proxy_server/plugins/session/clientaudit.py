import re
import logging
from packaging import version
import pkg_resources
import yaml


class SSHClient():

    VERSION_REGEX = None

    def __init__(self, client_version, vulnerability_list) -> None:
        self.client_version = client_version
        self.vulnerability_list = vulnerability_list

    def get_version_string(self):
        if not self.VERSION_REGEX:
            return None
        version_sring = re.match(self.VERSION_REGEX, self.client_version)
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

    def audit(self):
        found_cves = []
        for cve, description in self.vulnerability_list.items():
            version_min = description.get('version_min', "")
            version_max = description.get('version_max', "")
            if self.between_versions(version_min, version_max):
                found_cves.append(cve)

        if found_cves:
            cvelist = "\n".join(["    - {0}: https://docs.ssh.mitm.at/{0}.html".format(cve) for cve in found_cves])
            logging.info("possible vulnerabilities found!\n{}".format(cvelist))


class PuTTY(SSHClient):
    VERSION_REGEX = r'ssh-2.0-putty_release_(0\.[0-9]+)'


class OpenSSH(SSHClient):
    VERSION_REGEX = r'ssh-2.0-openssh_([0-9]+\.[0-9]+)p?.*'


class Dropbear(SSHClient):
    VERSION_REGEX = r'ssh-2.0-dropbear_([0-9]+\.[0-9]+)'


def audit_client(client_version):
    client = None
    vulnerability_list = None
    try:
        vulndb = pkg_resources.resource_filename('ssh_proxy_server', 'data/client_vulnerabilities.yml')
        with open(vulndb) as file:
            vulnerability_list = yaml.load(file, Loader=yaml.FullLoader)
    except Exception:
        logging.exception("Error loading vulnerability database")
        return
    if 'putty' in client_version:
        client = PuTTY(client_version, vulnerability_list.get('putty', {}))
    elif 'openssh' in client_version:
        client = OpenSSH(client_version, vulnerability_list.get('openssh', {}))
    elif 'dropbear' in client_version:
        client = Dropbear()
    if client:
        client.audit()
