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

        cookie = m.get_bytes(16)  # cookie
        key_algo_list = m.get_list()  # key_algo_list
        server_key_algo_list = m.get_list()
        client_version = session.transport.remote_version.lower()

        logging.info("connected client version: %s", client_version)
        logging.debug("cookie: %s", cookie)
        logging.debug("key_algo_list: %s", key_algo_list)
        logging.debug("server_key_algo_list: %s", server_key_algo_list)

        cve202014002.check_key_negotiation(client_version, server_key_algo_list, session)
        cve202014145.check_key_negotiation(client_version, server_key_algo_list, session)

        m.rewind()
        # normal operation
        Transport._negotiate_keys(transport, m)

    session.transport._handler_table[common.MSG_KEXINIT] = intercept_key_negotiation
