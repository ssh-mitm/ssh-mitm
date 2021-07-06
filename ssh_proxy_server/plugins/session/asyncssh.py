import logging

CLIENT_NAME = 'asyncssh'
DEFAULT_ALGORITMS = [
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

def check_key_negotiation(client_version, server_host_key_algorithms, session):
    if CLIENT_NAME in client_version:
        for host_key_algo in DEFAULT_ALGORITMS:
            if server_host_key_algorithms == host_key_algo:
                logging.info("%s: Client connecting for the FIRST time!", CLIENT_NAME)
                break
        else:
            logging.info("%s: Client has a locally cached remote fingerprint!", CLIENT_NAME)
