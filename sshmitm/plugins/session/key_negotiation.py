import logging
import re
from typing import TYPE_CHECKING

from colored.colored import stylize, fg, attr  # type: ignore
import paramiko

import pkg_resources
import yaml
from paramiko.message import Message
from paramiko import Transport, common
from paramiko.ssh_exception import SSHException

from rich.markup import escape
from rich._emoji_codes import EMOJI

import sshmitm
from sshmitm.plugins.session.clientaudit import SSHClientAudit

if TYPE_CHECKING:
    from sshmitm.session import Session  # noqa


class KeyNegotiationData:

    def __init__(self, session: 'sshmitm.session.Session', message: Message) -> None:
        self.session = session
        self.client_version = session.transport.remote_version
        self.cookie = message.get_bytes(16)  # cookie (random bytes)
        self.kex_algorithms = message.get_list()  # kex_algorithms
        self.server_host_key_algorithms = message.get_list()
        self.encryption_algorithms_client_to_server = message.get_list()
        self.encryption_algorithms_server_to_client = message.get_list()
        self.mac_algorithms_client_to_server = message.get_list()
        self.mac_algorithms_server_to_client = message.get_list()
        self.compression_algorithms_client_to_server = message.get_list()
        self.compression_algorithms_server_to_client = message.get_list()
        self.languages_client_to_server = message.get_list()
        self.languages_server_to_client = message.get_list()
        self.first_kex_packet_follows = message.get_boolean()
        message.rewind()

    def show_debug_info(self) -> None:
        logging.debug(
            "%s connected client version: %s",
            EMOJI['information'],
            stylize(self.client_version, fg('green') + attr('bold'))
        )
        logging.debug("cookie: %s", self.cookie.hex())
        logging.debug("kex_algorithms: %s", escape(str(self.kex_algorithms)))
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

    def audit_client(self) -> None:
        client = None
        vulnerability_list = None
        client_version = self.client_version.lower()
        try:
            vulndb = pkg_resources.resource_filename('sshmitm', 'data/client_info.yml')
            with open(vulndb, 'r', encoding="utf-8") as file:
                vulnerability_list = yaml.safe_load(file)
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Error loading vulnerability database")
            return
        for client_name, client_info in vulnerability_list.items():
            for version_regex in client_info.get('version_regex'):
                if re.search(version_regex, client_version):
                    client = SSHClientAudit(self, client_version, client_name, client_info)
                    break
            else:
                continue
            break
        else:
            client = SSHClientAudit(self, client_version)

        client.run_audit()


def handle_key_negotiation(session: 'sshmitm.session.Session') -> None:
    # When really trying to implement connection accepting/forwarding based on CVE-14145
    # one should consider that clients who already accepted the fingerprint of the ssh-mitm server
    # will be connected through on their second connect and will get a changed keys error
    # (because they have a cached fingerprint and it looks like they need to be connected through)

    # pylint: disable=protected-access
    def intercept_key_negotiation(transport: paramiko.Transport, message: Message) -> None:
        # restore intercept, to not disturb re-keying if this significantly alters the connection
        transport._handler_table[common.MSG_KEXINIT] = Transport._negotiate_keys  # type: ignore

        key_negotiation_data = KeyNegotiationData(session, message)
        key_negotiation_data.show_debug_info()
        key_negotiation_data.audit_client()

        # normal operation
        try:
            Transport._negotiate_keys(transport, message)  # type: ignore
        except SSHException as ex:
            logging.error(str(ex))

    session.transport._handler_table[common.MSG_KEXINIT] = intercept_key_negotiation  # type: ignore
