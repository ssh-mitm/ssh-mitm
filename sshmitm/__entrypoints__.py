from typing import Dict, List

entry_points: Dict[str, List[str]] = {
    'SSHBaseForwarder': [
        'base = sshmitm.forwarders.ssh:SSHForwarder',
        'mirrorshell = sshmitm.plugins.ssh.mirrorshell:SSHMirrorForwarder',
        'noshell = sshmitm.plugins.ssh.noshell:NoShellForwarder'
    ],
    'SCPBaseForwarder': [
        'base = sshmitm.forwarders.scp:SCPForwarder',
        'debug_traffic = sshmitm.plugins.scp.debug_traffic:SCPDebugForwarder',
        'inject_file = sshmitm.plugins.scp.inject_file:SCPInjectFile',
        'replace_file = sshmitm.plugins.scp.replace_file:SCPReplaceFile',
        'store_file = sshmitm.plugins.scp.store_file:SCPStorageForwarder',
        'replace-command = sshmitm.plugins.scp.rewrite_command:SCPRewriteCommand',
        'CVE-2022-29154 = sshmitm.plugins.scp.cve202229154:CVE202229154'
    ],
    'BaseSFTPServerInterface': [
        'base = sshmitm.interfaces.sftp:SFTPProxyServerInterface'
    ],
    'SFTPHandlerBasePlugin': [
        'base = sshmitm.forwarders.sftp:SFTPHandlerPlugin',
        'replace_file = sshmitm.plugins.sftp.replace_file:SFTPProxyReplaceHandler',
        'store_file = sshmitm.plugins.sftp.store_file:SFTPHandlerStoragePlugin'
    ],
    'RemotePortForwardingBaseForwarder': [
        'base = sshmitm.forwarders.tunnel:RemotePortForwardingForwarder',
        'inject = sshmitm.plugins.tunnel.injectservertunnel:InjectableRemotePortForwardingForwarder'
    ],
    'LocalPortForwardingBaseForwarder': [
        'base = sshmitm.forwarders.tunnel:LocalPortForwardingForwarder',
        'socks = sshmitm.plugins.tunnel.socks:SOCKSTunnelForwarder',
        'socks4 = sshmitm.plugins.tunnel.socks4:SOCKS4TunnelForwarder',
        'socks5 = sshmitm.plugins.tunnel.socks5:SOCKS5TunnelForwarder'
    ],
    'BaseServerInterface': [
        'base = sshmitm.interfaces.server:ServerInterface'
    ],
    'BaseSSHProxyManager': [
        'base = sshmitm.interfaces.server:SSHProxyManager'
    ],
    'Authenticator': [
        'passthrough = sshmitm.authentication:AuthenticatorPassThrough'
    ]
}
