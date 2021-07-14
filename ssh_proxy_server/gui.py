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

from gooey import Gooey, GooeyParser


@Gooey(
    program_name='SSH-MITM {}'.format(ssh_mitm_version),
    program_description='ssh man in the middle (ssh-mitm) server for security audits',
    tabbed_groups=True,
    optional_cols=1,
    default_size=(610, 590),
)
def main():

    if os.environ.get('APPIMAGE', None):
        # if running as appimage, remove empty arguments
        if len(sys.argv) == 2 and sys.argv[-1] == '':
            sys.argv = sys.argv[:-1]

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    logformatter = logging.Formatter('%(asctime)s [%(levelname)s]  %(message)s')
    for handler in root_logger.handlers:
        handler.setFormatter(logformatter)
    logging.getLogger("paramiko").setLevel(logging.WARNING)


    parser = GooeyParser(description='SSH Proxy Server')

    basicsettings = parser.add_argument_group("Basic settings")
    basicsettings.add_argument(
        '--banner-name',
        metavar='SSH banner',
        dest='banner_name',
        default='SSHMITM_{}'.format(ssh_mitm_version),
        help='set a custom string as server banner'
    )
    basicsettings.add_argument(
        '--listen-port',
        metavar='listen port',
        dest='listen_port',
        default=10022,
        type=int,
        help='listen port'
    )
    basicsettings.add_argument(
        '--request-agent',
        metavar='request agent',
        dest='request_agent',
        action='store_true',
        help='request agent for public key authentication'
    )

    hostkeysettings = parser.add_argument_group("Server host key")
    hostkeysettings.add_argument(
        '--host-key',
        metavar='host key file (optional)',
        dest='host_key',
        help='host key file',
        widget="FileChooser"
    )
    hostkeysettings.add_argument(
        '--host-key-algorithm',
        metavar='type of host key',
        dest='host_key_algorithm',
        default='rsa',
        choices=['dss', 'rsa', 'ecdsa', 'ed25519'],
        help='host key algorithm (default rsa)'
    )
    hostkeysettings.add_argument(
        '--host-key-length',
        metavar='host key length',
        dest='host_key_length',
        default=2048,
        type=int,
        help='host key length for dss and rsa (default 2048)'
    )

    args = parser.parse_args()

    Transport._CLIENT_ID = args.banner_name
    Transport.run = dropbear.transport_run

    authenticator = AuthenticatorPassThrough
    authenticator.REQUEST_AGENT = args.request_agent

    SSHProxyServer(
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
    ).start()


if __name__ == '__main__':
    main()
