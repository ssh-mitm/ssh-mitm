import logging
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

from ssh_proxy_server.forwarders.tunnel import (
    ServerTunnelBaseForwarder,
    ClientTunnelForwarder,
    ServerTunnelForwarder,
    ClientTunnelBaseForwarder
)

from ssh_proxy_server.workarounds import dropbear
from ssh_proxy_server.plugins.ssh.mirrorshell import SSHMirrorForwarder
from ssh_proxy_server.__version__ import version as ssh_mitm_version


def main():
    parser = ModuleParser(description='SSH Proxy Server', modules_from_file=True)

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
        help='host key file'
    )
    parser.add_argument(
        '--host-key-algorithm',
        dest='host_key_algorithm',
        default='rsa',
        choices=['dss', 'rsa', 'ecdsa', 'ed25519'],
        help='host key algorithm (default rsa)'
    )
    parser.add_argument(
        '--host-key-length',
        dest='host_key_length',
        default=2048,
        type=int,
        help='host key length for dss and rsa (default 2048)'
    )
    parser.add_module(
        '--ssh-interface',
        dest='ssh_interface',
        default=SSHMirrorForwarder,
        help='interface to handle terminal sessions',
        baseclass=SSHBaseForwarder
    )
    parser.add_module(
        '--scp-interface',
        dest='scp_interface',
        default=SCPForwarder,
        help='interface to handle scp file transfers',
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
        '--server-tunnel',
        dest='server_tunnel_interface',
        default=ServerTunnelForwarder,
        help='interface to handle tunnels from the server',
        baseclass=ServerTunnelBaseForwarder
    )
    parser.add_module(
        '--client-tunnel',
        dest='client_tunnel_interface',
        default=ClientTunnelForwarder,
        help='interface to handle tunnels from the client',
        baseclass=ClientTunnelBaseForwarder
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
        dest='request_agent',
        action='store_true',
        help='request agent for public key authentication'
    )
    parser.add_argument(
        '--request-agent-breakin',
        dest='request_agent_breakin',
        action='store_true',
        help='enables agent forwarding and tryies to break in to the agent, if not forwarded'
    )
    parser.add_argument(
        '--banner-name',
        dest='banner_name',
        default='SSHMITM_{}'.format(ssh_mitm_version),
        help='set a custom string as server banner'
    )
    parser.add_argument(
        '--paramiko-log-level',
        dest='paramiko_log_level',
        default='warning',
        choices=['warning', 'info', 'debug'],
        help='set paramikos log level'
    )
    parser.add_argument(
        '--disable-workarounds',
        dest='disable_workarounds',
        action='store_true',
        help='disable paramiko workarounds'
    )
    parser.add_argument(
        '--version',
        action='store_true',
        help='show version'
    )

    args = parser.parse_args()

    if args.version:
        print("SSH-MITM {}".format(ssh_mitm_version))
        return

    if not args.disable_workarounds:
        Transport.run = dropbear.transport_run

    if args.paramiko_log_level == 'debug':
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
    elif args.paramiko_log_level == 'info':
        logging.getLogger("paramiko").setLevel(logging.INFO)
    else:
        logging.getLogger("paramiko").setLevel(logging.WARNING)

    args.authenticator.REQUEST_AGENT = args.request_agent
    if args.request_agent_breakin:
        args.authenticator.REQUEST_AGENT = True
        args.authenticator.REQUEST_AGENT_BREAKIN = True

    logging.info("starting SSH-MITM %s", ssh_mitm_version)
    proxy = SSHProxyServer(
        args.listen_port,
        key_file=args.host_key,
        key_algorithm=args.host_key_algorithm,
        key_length=args.host_key_length,
        ssh_interface=args.ssh_interface,
        scp_interface=args.scp_interface,
        sftp_interface=args.sftp_interface,
        sftp_handler=args.sftp_handler,
        server_tunnel_interface=args.server_tunnel_interface,
        client_tunnel_interface=args.client_tunnel_interface,
        authentication_interface=args.auth_interface,
        authenticator=args.authenticator,
        transparent=args.transparent,
        args=args
    )
    if args.banner_name is not None:
        Transport._CLIENT_ID = args.banner_name
    proxy.start()


if __name__ == '__main__':
    main()
