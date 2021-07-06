import logging

CLIENT_NAME = 'ruby/net::ssh'
DEFAULT_ALGORITMS = [
    [  # ruby/net::ssh_5.2.0 x86_64-linux-gnu
        'ssh-ed25519-cert-v01@openssh.com', 'ssh-ed25519', 'ecdsa-sha2-nistp521-cert-v01@openssh.com',
        'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
        'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256', 'ssh-rsa-cert-v01@openssh.com',
        'ssh-rsa-cert-v00@openssh.com', 'ssh-rsa', 'ssh-dss'
    ]
]

def check_key_negotiation(client_version, server_host_key_algorithms, session):
    if CLIENT_NAME in client_version:
        for host_key_algo in DEFAULT_ALGORITMS:
            if server_host_key_algorithms == host_key_algo:
                logging.info("%s: Client connecting for the FIRST time!", CLIENT_NAME)
                break
        else:
            logging.info("%s: Client has a locally cached remote fingerprint!", CLIENT_NAME)
