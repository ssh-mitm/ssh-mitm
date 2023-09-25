import argparse

from sshmitm import __version__ as ssh_mitm_version
from sshmitm.moduleparser import ModuleParser
from sshmitm.server import SSHProxyServer

from sshmitm.authentication import (
    Authenticator,
)
from sshmitm.interfaces.server import (
    BaseServerInterface,
)
from sshmitm.forwarders.scp import SCPBaseForwarder
from sshmitm.forwarders.ssh import SSHBaseForwarder
from sshmitm.forwarders.sftp import SFTPHandlerBasePlugin

from sshmitm.interfaces.sftp import (
    BaseSFTPServerInterface,
)

from sshmitm.forwarders.tunnel import (
    RemotePortForwardingBaseForwarder,
    LocalPortForwardingBaseForwarder
)

from sshmitm.session import BaseSession


def init_server_parser(parser: ModuleParser) -> None:
    parser.add_module(
        '--ssh-interface',
        dest='ssh_interface',
        help='interface to handle terminal sessions',
        baseclass=SSHBaseForwarder
    )
    parser.add_module(
        '--scp-interface',
        dest='scp_interface',
        help='interface to handle scp file transfers',
        baseclass=SCPBaseForwarder
    )
    parser.add_module(
        '--sftp-interface',
        dest='sftp_interface',
        help='SFTP Handler to handle sftp file transfers',
        baseclass=BaseSFTPServerInterface
    )
    parser.add_module(
        '--sftp-handler',
        dest='sftp_handler',
        help='SFTP Handler to handle sftp file transfers',
        baseclass=SFTPHandlerBasePlugin
    )
    parser.add_module(
        '--remote-port-forwarder',
        dest='server_tunnel_interface',
        help='interface to handle tunnels from the server',
        baseclass=RemotePortForwardingBaseForwarder
    )
    parser.add_module(
        '--local-port-forwarder',
        dest='client_tunnel_interface',
        help='interface to handle tunnels from the client',
        baseclass=LocalPortForwardingBaseForwarder
    )
    parser.add_module(
        '--auth-interface',
        dest='auth_interface',
        baseclass=BaseServerInterface,
        help='interface for authentication'
    )
    parser.add_module(
        '--authenticator',
        dest='authenticator',
        baseclass=Authenticator,
        help='module for user authentication'
    )
    parser.add_module(
        '--session-class',
        dest='session_class',
        baseclass=BaseSession,
        help='custom session class for SSH-MITM'
    )

    parser_group = parser.add_argument_group(
        'SSH-Server-Options',
        'options for the integrated ssh server',
        config_section='SSH-Server-Options'
    )
    parser_group.add_argument(
        '--listen-port',
        dest='listen_port',
        type=int,
        help='listen port'
    )
    parser_group.add_argument(
        '--transparent',
        dest='transparent',
        action='store_true',
        help='enables transparent mode (requires root)'
    )
    parser_group.add_argument(
        '--host-key',
        dest='host_key',
        help='host key file'
    )
    parser_group.add_argument(
        '--host-key-algorithm',
        dest='host_key_algorithm',
        choices=['dss', 'rsa', 'ecdsa', 'ed25519'],
        help='host key algorithm (default rsa)'
    )
    parser_group.add_argument(
        '--host-key-length',
        dest='host_key_length',
        type=int,
        help='host key length for dss and rsa (default 2048)'
    )
    parser_group.add_argument(
        '--request-agent-breakin',
        dest='request_agent_breakin',
        action='store_true',
        help='enables agent forwarding and tryies to break in to the agent, if not forwarded'
    )
    parser_group.add_argument(
        '--banner-name',
        dest='banner_name',
        default=f'SSHMITM_{ssh_mitm_version}',
        help='set a custom string as server banner'
    )


def run_server(args: argparse.Namespace) -> None:
    if args.request_agent_breakin:
        args.authenticator.REQUEST_AGENT_BREAKIN = True

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
        banner_name=args.banner_name,
        debug=args.debug
    )
    proxy.print_serverinfo(args.log_format == 'json')
    proxy.start()
