import argparse

from rich import print as rich_print

from paramiko import Transport

from sshmitm.__version__ import version as ssh_mitm_version
from sshmitm.moduleparser import ModuleParser
from sshmitm.console import sshconsole
from sshmitm.server import SSHProxyServer

from sshmitm.authentication import (
    Authenticator,
    AuthenticatorPassThrough
)
from sshmitm.interfaces.server import (
    BaseServerInterface,
    ServerInterface
)
from sshmitm.forwarders.scp import SCPBaseForwarder
from sshmitm.forwarders.ssh import SSHBaseForwarder
from sshmitm.forwarders.sftp import SFTPHandlerBasePlugin

from sshmitm.interfaces.sftp import (
    BaseSFTPServerInterface,
    SFTPProxyServerInterface
)

from sshmitm.forwarders.tunnel import (
    RemotePortForwardingBaseForwarder,
    LocalPortForwardingBaseForwarder
)

from sshmitm.plugins.ssh.mirrorshell import SSHMirrorForwarder
from sshmitm.plugins.scp.store_file import SCPStorageForwarder
from sshmitm.plugins.sftp.store_file import SFTPHandlerStoragePlugin
from sshmitm.plugins.tunnel.injectservertunnel import InjectableRemotePortForwardingForwarder
from sshmitm.plugins.tunnel.socks import SOCKSTunnelForwarder
from sshmitm.session import BaseSession, Session


def init_server_parser(parser: ModuleParser) -> None:
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
        default=SCPStorageForwarder,
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
        default=SFTPHandlerStoragePlugin,
        help='SFTP Handler to handle sftp file transfers',
        baseclass=SFTPHandlerBasePlugin
    )
    parser.add_module(
        '--remote-port-forwarder',
        dest='server_tunnel_interface',
        default=InjectableRemotePortForwardingForwarder,
        help='interface to handle tunnels from the server',
        baseclass=RemotePortForwardingBaseForwarder
    )
    parser.add_module(
        '--local-port-forwarder',
        dest='client_tunnel_interface',
        default=SOCKSTunnelForwarder,
        help='interface to handle tunnels from the client',
        baseclass=LocalPortForwardingBaseForwarder
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
        '--request-agent-breakin',
        dest='request_agent_breakin',
        action='store_true',
        help='enables agent forwarding and tryies to break in to the agent, if not forwarded'
    )
    parser.add_argument(
        '--banner-name',
        dest='banner_name',
        default=f'SSHMITM_{ssh_mitm_version}',
        help='set a custom string as server banner'
    )
    parser.add_module(
        '--session-class',
        dest='session_class',
        default=Session,
        baseclass=BaseSession,
        help=argparse.SUPPRESS
    )


def run_server(args: argparse.Namespace) -> None:
    if args.request_agent_breakin:
        args.authenticator.REQUEST_AGENT_BREAKIN = True

    print('\33]0;SSH-MITM - ssh audits made simple\a', end='', flush=True)
    sshconsole.rule("[bold blue]SSH-MITM - ssh audits made simple", style="blue")
    rich_print(f'[bold]Version:[/bold] {ssh_mitm_version}')
    rich_print('[bold]License:[/bold] GNU General Public License v3.0')
    rich_print("[bold]Documentation:[/bold] https://docs.ssh-mitm.at")
    rich_print("[bold]Issues:[/bold] https://github.com/ssh-mitm/ssh-mitm/issues")
    sshconsole.rule(style="blue")

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
        Transport._CLIENT_ID = args.banner_name  # type: ignore
    proxy.start()
