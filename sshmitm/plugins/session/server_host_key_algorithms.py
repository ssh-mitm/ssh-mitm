"""
The variable SERVER_HOST_KEY_ALGORITHMS is a dictionary containing information on the
server host key algorithms supported by different SSH clients.

Each key in the dictionary represents a different SSH client, and the value for each key
is either a list of algorithms supported by that client, the name of another key in the
dictionary (referring to the same algorithm list), or None indicating that the same algorithm
list is used as for "known hosts". The algorithms are represented by strings in the format
algorithm-hash-cert-version@openssh.com or just algorithm-hash.
"""

from sshmitm.plugins.session import cve202014002, cve202014145

SERVER_HOST_KEY_ALGORITHMS = {
    'AbsoluteTelnet': None,  # same list for known hosts
    'AsyncSSH': [
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
    ],
    'Dropbear': None,  # same list for known hosts
    'JSCH': ['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'],
    'KiTTY': 'PuTTY_Release',
    'MoTTY_Release': 'PuTTY_Release',
    'OpenSSH': cve202014145.SERVER_HOST_KEY_ALGORITHMS,
    'Paramiko': None,  # same list for known hosts
    'PuTTYFileZilla': 'PuTTY_Release',
    'PuTTY_Release': cve202014002.SERVER_HOST_KEY_ALGORITHMS,
    'RubyNetSsh': [
        [  # ruby/net::ssh_5.2.0 x86_64-linux-gnu
            'ssh-ed25519-cert-v01@openssh.com', 'ssh-ed25519', 'ecdsa-sha2-nistp521-cert-v01@openssh.com',
            'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256', 'ssh-rsa-cert-v01@openssh.com',
            'ssh-rsa-cert-v00@openssh.com', 'ssh-rsa', 'ssh-dss'
        ]
    ],
    'SecureBlackbox': None,  # same list for known hosts
    'TeraTermVT': None,  # same list for known hosts
    'TTYEmulator': None,  # same list for known hosts
    'WinSCP': 'PuTTY_Release',
    'WolfSSH': None,  # same list for known hosts
}
"""
dictionary mapping various SSH client implementations to the algorithms they support for server host keys
"""
