import logging
import sys
import os

from paramiko import Transport

from ssh_proxy_server.server import SSHProxyServer

from ssh_proxy_server.authentication import AuthenticatorPassThrough
from ssh_proxy_server.interfaces import ServerInterface
from ssh_proxy_server.forwarders.scp import SCPForwarder
from ssh_proxy_server.forwarders.sftp import SFTPHandlerPlugin

from ssh_proxy_server.interfaces.sftp import SFTPProxyServerInterface

from ssh_proxy_server.forwarders.tunnel import (
    ClientTunnelForwarder,
    ServerTunnelForwarder,
)

from ssh_proxy_server.workarounds import dropbear
from ssh_proxy_server.plugins.ssh.mirrorshell import SSHMirrorForwarder
from ssh_proxy_server.__version__ import version as ssh_mitm_version

try:
    from gooey import Gooey, GooeyParser
except ImportError:
    def Gooey(*args, **kwargs):
        def wrapper(func):
            if os.environ.get('APPIMAGE', None):
                print("SSH-MITM GUI not available from an AppImage!")
                print("Please install SSH-MITM with pip:\n   pip install ssh-mitm[gui]")
                print("You can also install SSH-MITM as Snap:\n   snap install ssh-mitm")
            else:
                logging.error("Gooey not installed! Please install it with: pip install Gooey")
            sys.exit(1)
        return wrapper


@Gooey(
    program_name='SSH-MITM {}'.format(ssh_mitm_version),
    program_description='ssh man in the middle (ssh-mitm) server for security audits',
    tabbed_groups=True,
    optional_cols=1,
    default_size=(610, 590),
    richtext_controls=True,
    clear_before_run=True,
    menu=[{
        'name': 'Help',
        'items': [
            {
                'type': 'Link',
                'menuTitle': 'Documentation',
                'url': 'https://docs.ssh-mitm.at'
            },{
                'type': 'AboutDialog',
                'menuTitle': 'About',
                'name': 'SSH-MITM',
                'description': 'ssh man in the middle (ssh-mitm) server for security audits',
                'version': ssh_mitm_version,
                'website': 'https://www.ssh-mitm.at',
                'developer': 'https://github.com/ssh-mitm/ssh-mitm',
                'license': 'LGPL-3.0 License '
            }
        ]
    }]
)
def main():
    logging.basicConfig(format='%(message)s', level=logging.INFO)
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

    remotehostsettings = parser.add_argument_group("Remote Host")
    remotehostsettings.add_argument(
        '--remote-host',
        dest='remote_host',
        help='remote host to connect to (default 127.0.0.1)'
    )
    remotehostsettings.add_argument(
        '--remote-port',
        dest='remote_port',
        type=int,
        help='remote port to connect to (default 22)'
    )
    remotehostsettings.add_argument(
        '--auth-username',
        dest='auth_username',
        help='username for remote authentication'
    )
    remotehostsettings.add_argument(
        '--auth-password',
        dest='auth_password',
        help='password for remote authentication',
        widget='PasswordField'
    )
    remotehostsettings.add_argument(
        '--forward-agent',
        dest='forward_agent',
        action='store_true',
        help='enables agent forwarding through the proxy'
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
