from typing import Dict, List

entry_points: Dict[str, List[str]] = {
    'SSHBaseForwarder': [
        'base = ssh_proxy_server.forwarders.ssh:SSHForwarder',
        'mirrorshell = ssh_proxy_server.plugins.ssh.mirrorshell:SSHMirrorForwarder',
        'noshell = ssh_proxy_server.plugins.ssh.noshell:NoShellForwarder'
    ],
    'SCPBaseForwarder': [
        'base = ssh_proxy_server.forwarders.scp:SCPForwarder',
        'debug_traffic = ssh_proxy_server.plugins.scp.debug_traffic:SCPDebugForwarder',
        'inject_file = ssh_proxy_server.plugins.scp.inject_file:SCPInjectFile',
        'replace_file = ssh_proxy_server.plugins.scp.replace_file:SCPReplaceFile',
        'store_file = ssh_proxy_server.plugins.scp.store_file:SCPStorageForwarder'
    ],
    'BaseSFTPServerInterface': [
        'base = ssh_proxy_server.interfaces.sftp:SFTPProxyServerInterface'
    ],
    'SFTPHandlerBasePlugin': [
        'base = ssh_proxy_server.forwarders.sftp:SFTPHandlerPlugin',
        'replace_file = ssh_proxy_server.plugins.sftp.replace_file:SFTPProxyReplaceHandler',
        'store_file = ssh_proxy_server.plugins.sftp.store_file:SFTPHandlerStoragePlugin'
    ],
    'RemotePortForwardingBaseForwarder': [
        'base = ssh_proxy_server.forwarders.tunnel:RemotePortForwardingForwarder',
        'inject = ssh_proxy_server.plugins.tunnel.injectservertunnel:InjectableRemotePortForwardingForwarder'
    ],
    'LocalPortForwardingBaseForwarder': [
        'base = ssh_proxy_server.forwarders.tunnel:LocalPortForwardingForwarder',
        'socks4 = ssh_proxy_server.plugins.tunnel.socks4:SOCKS4TunnelForwarder',
        'socks5 = ssh_proxy_server.plugins.tunnel.socks5:SOCKS5TunnelForwarder'
    ],
    'BaseServerInterface': [
        'base = ssh_proxy_server.interfaces.server:ServerInterface'
    ],
    'BaseSSHProxyManager': [
        'base = ssh_proxy_server.interfaces.server:SSHProxyManager'
    ],
    'Authenticator': [
        'passthrough = ssh_proxy_server.authentication:AuthenticatorPassThrough'
    ]
}
