from enhancements.modules import ModuleParser
from enhancements.plugins import LogModule

from paramiko import Transport

from ssh_proxy_server.server import SSHProxyServer

from ssh_proxy_server.authentication import (
    Authenticator,
    AuthenticatorPassThrough
)
from ssh_proxy_server.interfaces import (
    BaseServerInterface,
    ServerInterface
)
from ssh_proxy_server.forwarders.base import BaseForwarder
from ssh_proxy_server.forwarders.scp import (
    SCPBaseForwarder,
    SCPForwarder
)
from ssh_proxy_server.forwarders.ssh import (
    SSHBaseForwarder
)
from ssh_proxy_server.forwarders.sftp import (
    SFTPHandlerBasePlugin,
    SFTPHandlerPlugin
)

from ssh_proxy_server.interfaces.sftp import (
    BaseSFTPServerInterface,
    SFTPProxyServerInterface
)

from ssh_proxy_server.plugins.ssh.mirrorshell import SSHMirrorForwarder


def main():
    parser = ModuleParser(description='SSH Proxy Server', baseclass=BaseForwarder, modules_from_file=True)

    parser.add_plugin(LogModule)

    parser.add_argument(
        '--listen-port',
        dest='listen_port',
        default=10022,
        type=int,
        help='listen port'
    )
    parser.add_argument(
        '--transparent',
        dest='transparent',
        action='store_true',
        help='enables transparent mode (requires root)'
    )
    parser.add_argument(
        '--host-key',
        dest='host_key',
        help='rsa host key'
    )
    parser.add_module(
        '--ssh-interface',
        dest='ssh_interface',
        default=SSHMirrorForwarder,
        help='ProxyManager to manage the Proxy',
        baseclass=SSHBaseForwarder
    )
    parser.add_module(
        '--scp-interface',
        dest='scp_interface',
        default=SCPForwarder,
        help='ProxyManager to manage the Proxy',
        baseclass=SCPBaseForwarder
    )
    parser.add_module(
        '--sftp-interface',
        dest='sftp_interface',
        default=SFTPProxyServerInterface,
        help='SFTP Handler to handle sftp file transfers',
        baseclass=BaseSFTPServerInterface
    )
    parser.add_module(
        '--sftp-handler',
        dest='sftp_handler',
        default=SFTPHandlerPlugin,
        help='SFTP Handler to handle sftp file transfers',
        baseclass=SFTPHandlerBasePlugin
    )
    parser.add_module(
        '--auth-interface',
        dest='auth_interface',
        default=ServerInterface,
        baseclass=BaseServerInterface,
        help='interface for authentication'
    )
    parser.add_module(
        '--authenticator',
        dest='authenticator',
        default=AuthenticatorPassThrough,
        baseclass=Authenticator,
        help='module for user authentication'
    )
    parser.add_argument(
        '--request-agent',
        dest='foreward_agent',
        action='store_true',
        help='enables agent forwarding'
    )
    parser.add_argument(
        '--banner-name',
        dest='banner_name',
        help='set a custom string as server banner'
    )

    args = parser.parse_args()

    args.authenticator.REQUEST_AGENT = args.foreward_agent

    proxy = SSHProxyServer(
        args.listen_port,
        key_file=args.host_key,
        ssh_interface=args.ssh_interface,
        scp_interface=args.scp_interface,
        sftp_interface=args.sftp_interface,
        sftp_handler=args.sftp_handler,
        authentication_interface=args.auth_interface,
        authenticator=args.authenticator,
        transparent=args.transparent
    )
    if args.banner_name is not None:
        Transport._CLIENT_ID = args.banner_name
    proxy.start()


if __name__ == '__main__':
    main()
