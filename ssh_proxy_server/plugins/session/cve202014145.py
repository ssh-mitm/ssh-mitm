import logging
import re

from paramiko import ECDSAKey


CVE = 'CVE-2020-14145'
CLIENT_NAME = 'openssh'
DEFAULT_ALGORITMS = [
    [  # client version: OpenSSH_8.5p1 - OpenSSH_8.6p1
        'ssh-ed25519-cert-v01@openssh.com', 'ecdsa-sha2-nistp256-cert-v01@openssh.com', 
        'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp521-cert-v01@openssh.com', 
        'sk-ssh-ed25519-cert-v01@openssh.com', 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com', 
        'rsa-sha2-512-cert-v01@openssh.com', 'rsa-sha2-256-cert-v01@openssh.com', 
        'ssh-rsa-cert-v01@openssh.com', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 
        'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'sk-ssh-ed25519@openssh.com', 
        'sk-ecdsa-sha2-nistp256@openssh.com', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'],

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


def check_key_negotiation(client_version, server_host_key_algorithms, session):
    if CLIENT_NAME in client_version:
        if isinstance(session.proxyserver.host_key, ECDSAKey):
            logging.warning("%s: ecdsa-sha2 key is a bad choice; this will produce false positives!", CVE)
        r = re.compile(r".*openssh_(\d\.\d).*", re.IGNORECASE)
        if int(r.match(session.transport.remote_version).group(1).replace(".", "")) > 83:
            logging.warning("%s: Remote OpenSSH Version > 8.3; CVE-2020-14145 might produce false positive!", CVE)

        for host_key_algo in DEFAULT_ALGORITMS:
            if server_host_key_algorithms == host_key_algo:
                logging.info("%s: Client connecting for the FIRST time!", CVE)
                break
        else:
            logging.info("%s: Client has a locally cached remote fingerprint!", CVE)
