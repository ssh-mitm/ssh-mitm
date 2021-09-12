import logging
import sys
import os

from paramiko import Transport

from ssh_proxy_server.server import SSHProxyServer

from ssh_proxy_server.authentication import AuthenticatorPassThrough
from ssh_proxy_server.interfaces import ServerInterface
from ssh_proxy_server.plugins.scp.store_file import SCPStorageForwarder
from ssh_proxy_server.plugins.sftp.store_file import SFTPHandlerStoragePlugin

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
    program_name=f'SSH-MITM {ssh_mitm_version}',
    program_description='ssh audits made simple',
    tabbed_groups=True,
    optional_cols=1,
    default_size=(550, 650),
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
                'type': 'Link',
                'menuTitle': 'Report an issue',
                'url': 'https://github.com/ssh-mitm/ssh-mitm/issues'
            },{
                'type': 'AboutDialog',
                'menuTitle': 'About',
                'name': 'SSH-MITM',
                'description': 'ssh audits made simple',
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

    remotehostsettings = parser.add_argument_group("Connection settings")
    remotehostsettings.add_argument(
        '--listen-port',
        metavar='listen port',
        dest='listen_port',
        default=10022,
        type=int,
        help='listen port (default 10022)'
    )
    remotehostsettings.add_argument(
        '--remote-host',
        dest='remote_host',
        default='127.0.0.1',
        metavar='remote host',
        help='remote host to connect to (default 127.0.0.1)'
    )
    remotehostsettings.add_argument(
        '--remote-port',
        dest='remote_port',
        metavar='remote port',
        default=22,
        type=int,
        help='remote port to connect to (default 22)'
    )
    remotehostsettings.add_argument(
            '--hide-credentials',
            dest='auth_hide_credentials',
            metavar='hide credentials',
            action='store_true',
            help='do not log credentials (usefull for presentations)'
        )

    hostkeysettings = parser.add_argument_group("Server host key")
    hostkeysettings.add_argument(
        '--host-key',
        metavar='host key file (optional)',
        dest='host_key',
        help='host key file, if not provided temorary key will be generated',
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

    logsettings = parser.add_argument_group("Logging")
    logsettings.add_argument(
        '--session-log-dir',
        metavar='terminal session logdir (optional)',
        dest='ssh_log_dir',
        help='directory to store ssh session logs',
        widget="DirChooser"
    )
    logsettings.add_argument(
        '--store-ssh-session',
        metavar='save terminal session log',
        dest='store_ssh_session',
        action='store_true',
        help='this options stores terminal sessions in a scriptreplay compatible format'
    )
    logsettings.add_argument(
        '--store-scp-files',
        metavar='store SCP file transfers',
        dest='store_scp_files',
        action='store_true',
        help='store files from scp'
    )
    logsettings.add_argument(
        '--store-sftp-files',
        dest='store SFTP file transfers',
        action='store_true',
        help='store files from sftp'
    )

    honeypotsettings = parser.add_argument_group(
        "Honeypot",
        description="\n".join([
            'Optional settings to fallback to a honeypot if publickey authentication failed.',
            'This happens, when no agent was forwarded from the client.',
            'When not enabled, SSH-MITM closes the connection.',
            '',
            'SSH-MITM is able to check if a user is allowed to login to a remote host,',
            'but due to a missing forwarded agent, authentication to the remote host is not possible.'
        ])
    )
    honeypotsettings.add_argument(
        '--enable-auth-fallback',
        metavar='Enable Honeypot (optional)',
        dest='enable_auth_fallback',
        action='store_true',
        help='fallback to a honeypot when publickey authentication failed'
    )
    honeypotsettings.add_argument(
        '--fallback-host',
        dest='fallback_host',
        metavar='Honeypot-Host',
        required='--enable-auth-fallback' in sys.argv,
        help='fallback host for the honey'
    )
    honeypotsettings.add_argument(
        '--fallback-port',
        dest='fallback_port',
        metavar='Honeypot-Port',
        type=int,
        default=22,
        help='fallback port for the honeypot (default: 22)'
    )
    honeypotsettings.add_argument(
        '--fallback-username',
        dest='fallback_username',
        metavar='Honeypot-Username',
        required='--enable-auth-fallback' in sys.argv,
        help='username, which is used to to login to the honeypot'
    )
    honeypotsettings.add_argument(
        '--fallback-password',
        dest='fallback_password',
        metavar='Honeypot-Password',
        required='--enable-auth-fallback' in sys.argv,
        help='password, which is used to to login to the honeypot'
    )

    args = parser.parse_args()

    Transport.run = dropbear.transport_run

    SSHProxyServer(
        args.listen_port,
        key_file=args.host_key,
        key_algorithm=args.host_key_algorithm,
        key_length=args.host_key_length,
        ssh_interface=SSHMirrorForwarder,
        scp_interface=SCPStorageForwarder,
        sftp_interface=SFTPProxyServerInterface,
        sftp_handler=SFTPHandlerStoragePlugin,
        server_tunnel_interface=ServerTunnelForwarder,
        client_tunnel_interface=ClientTunnelForwarder,
        authentication_interface=ServerInterface,
        authenticator=AuthenticatorPassThrough,
        transparent=False,
        args=args
    ).start()


if __name__ == '__main__':
    main()
