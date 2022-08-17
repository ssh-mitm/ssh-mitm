SERVER_HOST_KEY_ALGORITHMS = [
    [
        'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa', 'ssh-dss'
    ],
    [  # ssh-2.0-putty_release_0.76
        'ssh-ed448', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa', 'ssh-dss'
    ]
]
