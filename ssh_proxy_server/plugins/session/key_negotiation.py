import logging

import pkg_resources
import yaml
from paramiko import Transport, common


from ssh_proxy_server.plugins.session.clientaudit import SSHClientAudit


class KeyNegotiationData:

    def __init__(self, session, m):
        self.session = session
        self.client_version = session.transport.remote_version
        self.cookie = m.get_bytes(16)  # cookie (random bytes)
        self.kex_algorithms = m.get_list()  # kex_algorithms
        self.server_host_key_algorithms = m.get_list()
        self.encryption_algorithms_client_to_server = m.get_list()
        self.encryption_algorithms_server_to_client = m.get_list()
        self.mac_algorithms_client_to_server = m.get_list()
        self.mac_algorithms_server_to_client = m.get_list()
        self.compression_algorithms_client_to_server = m.get_list()
        self.compression_algorithms_server_to_client = m.get_list()
        self.languages_client_to_server = m.get_list()
        self.languages_server_to_client = m.get_list()
        self.first_kex_packet_follows = m.get_boolean()
        m.rewind()

    def show_debug_info(self):
        logging.info("connected client version: %s", self.client_version)
        logging.debug("cookie: %s", self.cookie)
        logging.debug("kex_algorithms: %s", self.kex_algorithms)
        logging.debug("server_host_key_algorithms: %s", self.server_host_key_algorithms)
        logging.debug("encryption_algorithms_client_to_server: %s", self.encryption_algorithms_client_to_server)
        logging.debug("encryption_algorithms_server_to_client: %s", self.encryption_algorithms_server_to_client)
        logging.debug("mac_algorithms_client_to_server: %s", self.mac_algorithms_client_to_server)
        logging.debug("mac_algorithms_server_to_client: %s", self.mac_algorithms_server_to_client)
        logging.debug("compression_algorithms_client_to_server: %s", self.compression_algorithms_client_to_server)
        logging.debug("compression_algorithms_server_to_client: %s", self.compression_algorithms_server_to_client)
        logging.debug("languages_client_to_server: %s", self.languages_client_to_server)
        logging.debug("languages_server_to_client: %s", self.languages_server_to_client)
        logging.debug("first_kex_packet_follows: %s", self.first_kex_packet_follows)

    def audit_client(self):
        client = None
        vulnerability_list = None
        client_version = self.client_version.lower()
        try:
            vulndb = pkg_resources.resource_filename('ssh_proxy_server', 'data/client_vulnerabilities.yml')
            with open(vulndb) as file:
                vulnerability_list = yaml.load(file, Loader=yaml.FullLoader)
        except Exception:
            logging.exception("Error loading vulnerability database")
            return
        for client_cls in SSHClientAudit.__subclasses__():
            if client_cls.client_name() in client_version:
                client = client_cls(self, vulnerability_list.get(client_cls.client_name(), {}))

        if client:
            client.check_cves()
            client.check_key_negotiation()
            client.audit()


def handle_key_negotiation(session):
    # When really trying to implement connection accepting/forwarding based on CVE-14145
    # one should consider that clients who already accepted the fingerprint of the ssh-mitm server
    # will be connected through on their second connect and will get a changed keys error
    # (because they have a cached fingerprint and it looks like they need to be connected through)
    def intercept_key_negotiation(transport, m):
        # restore intercept, to not disturb re-keying if this significantly alters the connection
        transport._handler_table[common.MSG_KEXINIT] = Transport._negotiate_keys

        key_negotiation_data = KeyNegotiationData(session, m)
        key_negotiation_data.show_debug_info()
        key_negotiation_data.audit_client()


        # normal operation
        Transport._negotiate_keys(transport, m)

    session.transport._handler_table[common.MSG_KEXINIT] = intercept_key_negotiation
