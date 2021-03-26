import logging

from paramiko import Transport, common

from ssh_proxy_server.plugins.session import cve202014002, cve202014145


def handle_key_negotiation(session):
    # When really trying to implement connection accepting/forwarding based on CVE-14145
    # one should consider that clients who already accepted the fingerprint of the ssh-mitm server
    # will be connected through on their second connect and will get a changed keys error
    # (because they have a cached fingerprint and it looks like they need to be connected through)
    def intercept_key_negotiation(transport, m):
        # restore intercept, to not disturb re-keying if this significantly alters the connection
        transport._handler_table[common.MSG_KEXINIT] = Transport._negotiate_keys

        client_version = session.transport.remote_version.lower()

        cookie = m.get_bytes(16)  # cookie (random bytes)
        kex_algorithms = m.get_list()  # kex_algorithms
        server_host_key_algorithms = m.get_list()
        encryption_algorithms_client_to_server = m.get_list()
        encryption_algorithms_server_to_client = m.get_list()
        mac_algorithms_client_to_server = m.get_list()
        mac_algorithms_server_to_client = m.get_list()
        compression_algorithms_client_to_server = m.get_list()
        compression_algorithms_server_to_client = m.get_list()
        languages_client_to_server = m.get_list()
        languages_server_to_client = m.get_list()
        first_kex_packet_follows = m.get_boolean()

        logging.info("connected client version: %s", client_version)
        logging.debug("cookie: %s", cookie)
        logging.debug("kex_algorithms: %s", kex_algorithms)
        logging.debug("server_host_key_algorithms: %s", server_host_key_algorithms)
        logging.debug("encryption_algorithms_client_to_server: %s", encryption_algorithms_client_to_server)
        logging.debug("encryption_algorithms_server_to_client: %s", encryption_algorithms_server_to_client)
        logging.debug("mac_algorithms_client_to_server: %s", mac_algorithms_client_to_server)
        logging.debug("mac_algorithms_server_to_client: %s", mac_algorithms_server_to_client)
        logging.debug("compression_algorithms_client_to_server: %s", compression_algorithms_client_to_server)
        logging.debug("compression_algorithms_server_to_client: %s", compression_algorithms_server_to_client)
        logging.debug("languages_client_to_server: %s", languages_client_to_server)
        logging.debug("languages_server_to_client: %s", languages_server_to_client)
        logging.debug("first_kex_packet_follows: %s", first_kex_packet_follows)

        cve202014002.check_key_negotiation(client_version, server_host_key_algorithms, session)
        cve202014145.check_key_negotiation(client_version, server_host_key_algorithms, session)

        m.rewind()
        # normal operation
        Transport._negotiate_keys(transport, m)

    session.transport._handler_table[common.MSG_KEXINIT] = intercept_key_negotiation
