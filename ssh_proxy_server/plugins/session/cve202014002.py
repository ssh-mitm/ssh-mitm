import logging
import re

from paramiko import ECDSAKey

CVE = 'CVE-2020-14002'
CLIENT_NAME = 'putty'
DEFAULT_ALGORITMS = [
    ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss']
]

def check_key_negotiation(client_version, server_host_key_algorithms, session):
    if CLIENT_NAME in client_version:
        if isinstance(session.proxyserver.host_key, ECDSAKey):
            logging.warning("%s: ecdsa-sha2 key is a bad choice; this will produce false positives!", CVE)
        for host_key_algo in DEFAULT_ALGORITMS:
            if server_host_key_algorithms == host_key_algo:
                logging.info("%s: Client connecting for the FIRST time!", CVE)
                break
        else:
            logging.info("%s: Client has a locally cached remote fingerprint!", CVE)
