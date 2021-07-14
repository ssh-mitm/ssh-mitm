import logging
import sys
import os

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

from gooey import Gooey

@Gooey
def main():

    if os.environ.get('APPIMAGE', None):
        # if running as appimage, remove empty arguments
        if len(sys.argv) == 2 and sys.argv[-1] == '':
            sys.argv = sys.argv[:-1]

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
    parser.add_argument(
        '--request-agent',
        dest='request_agent',
        action='store_true',
        help='request agent for public key authentication'
    )
    parser.add_argument(
        '--banner-name',
        dest='banner_name',
        default='SSHMITM_{}'.format(ssh_mitm_version),
        help='set a custom string as server banner'
    )

    args = parser.parse_args()

    Transport.run = dropbear.transport_run

    logging.getLogger("paramiko").setLevel(logging.WARNING)

    authenticator = AuthenticatorPassThrough
    authenticator.REQUEST_AGENT = args.request_agent

    logging.info("starting SSH-MITM %s", ssh_mitm_version)
    proxy = SSHProxyServer(
        args.listen_port,
        key_file=args.host_key,
        key_algorithm=args.host_key_algorithm,
        key_length=args.host_key_length,
        ssh_interface=SSHMirrorForwarder,
        scp_interface=SCPForwarder,
        sftp_interface=SFTPProxyServerInterface,
        sftp_handler=SFTPHandlerPlugin,
        server_tunnel_interface=ServerTunnelForwarder,
        client_tunnel_interface=ClientTunnelForwarder,
        authentication_interface=ServerInterface,
        authenticator=authenticator,
        transparent=False,
        args=args
    )
    if args.banner_name is not None:
        Transport._CLIENT_ID = args.banner_name
    proxy.start()


if __name__ == '__main__':
    main()
