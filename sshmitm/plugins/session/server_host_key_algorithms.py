from sshmitm.plugins.session import cve202014002, cve202014145

SERVER_HOST_KEY_ALGORITHMS = {
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
    'MoTTY_Release': [
        [
            'ssh-ed448', 'ssh-ed25519',
            'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521', 'rsa-sha2-512',
            'rsa-sha2-256', 'ssh-rsa', 'ssh-dss'
        ]
    ],
    'OpenSSH': cve202014145.SERVER_HOST_KEY_ALGORITHMS,
    'PuTTY_Release': cve202014002.SERVER_HOST_KEY_ALGORITHMS,
    'PuTTYFileZilla': [
        [
            'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss'
        ],
        [  # FileZilla 3.58.0
            'ssh-ed448', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ssh-dss'
        ]
    ],
    'RubyNetSsh': [
        [  # ruby/net::ssh_5.2.0 x86_64-linux-gnu
            'ssh-ed25519-cert-v01@openssh.com', 'ssh-ed25519', 'ecdsa-sha2-nistp521-cert-v01@openssh.com',
            'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
            'ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256', 'ssh-rsa-cert-v01@openssh.com',
            'ssh-rsa-cert-v00@openssh.com', 'ssh-rsa', 'ssh-dss'
        ]
    ],
    'WinSCP': [
        [
            'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss'
        ],
        [  # WinSCP-5.21.2-Portable
            'ssh-ed448', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
            'ecdsa-sha2-nistp521', 'rsa-sha2-512',
            'rsa-sha2-256', 'ssh-rsa', 'ssh-dss'
        ]
    ]
}
