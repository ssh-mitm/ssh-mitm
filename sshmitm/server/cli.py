import argparse

from sshmitm.authentication import Authenticator
from sshmitm.forwarders.agent import AgentBaseForwarder
from sshmitm.forwarders.netconf import NetconfBaseForwarder
from sshmitm.forwarders.powershell import PowerShellBaseForwarder
from sshmitm.forwarders.scp import SCPBaseForwarder
from sshmitm.forwarders.sftp import SFTPHandlerBasePlugin
from sshmitm.forwarders.ssh import SSHBaseForwarder
from sshmitm.forwarders.tunnel import (
    LocalPortForwardingBaseForwarder,
    RemotePortForwardingBaseForwarder,
)
from sshmitm.interfaces.server import BaseServerInterface
from sshmitm.interfaces.sftp import BaseSFTPServerInterface
from sshmitm.moduleparser import SubCommand
from sshmitm.server import SSHProxyServer
from sshmitm.session import BaseSession


class SSHServerModules(SubCommand):
    """start the ssh-mitm server"""

    @classmethod
    def config_section(cls) -> str | None:
        return "SSH-Server-Modules"

    def register_arguments(self) -> None:
        self.parser.add_module(
            "--netconf-interface",
            dest="netconf_interface",
            baseclass=NetconfBaseForwarder,
        )
        self.parser.add_module(
            "--powershell-interface",
            dest="powershell_interface",
            baseclass=PowerShellBaseForwarder,
        )
        self.parser.add_module(
            "--ssh-interface",
            dest="ssh_interface",
            baseclass=SSHBaseForwarder,
        )
        self.parser.add_module(
            "--scp-interface",
            dest="scp_interface",
            baseclass=SCPBaseForwarder,
        )
        self.parser.add_module(
            "--sftp-interface",
            dest="sftp_interface",
            baseclass=BaseSFTPServerInterface,
        )
        self.parser.add_module(
            "--sftp-handler",
            dest="sftp_handler",
            baseclass=SFTPHandlerBasePlugin,
        )
        self.parser.add_module(
            "--remote-port-forwarder",
            dest="server_tunnel_interface",
            baseclass=RemotePortForwardingBaseForwarder,
        )
        self.parser.add_module(
            "--local-port-forwarder",
            dest="client_tunnel_interface",
            baseclass=LocalPortForwardingBaseForwarder,
        )
        self.parser.add_module(
            "--auth-interface",
            dest="auth_interface",
            baseclass=BaseServerInterface,
        )
        self.parser.add_module(
            "--authenticator",
            dest="authenticator",
            baseclass=Authenticator,
        )
        self.parser.add_module(
            "--session-class",
            dest="session_class",
            baseclass=BaseSession,
        )
        self.parser.add_module(
            "--agent-forwarder",
            dest="agent_forwarder",
            baseclass=AgentBaseForwarder,
        )

        parser_group = self.parser.add_argument_group(
            "SSH-Server-Options",
            "Options for the integrated SSH server",
            config_section="SSH-Server-Options",
        )
        parser_group.add_argument(
            "--listen-address",
            dest="listen_address",
            help="Specifies the listen address for incoming connections (default: all interfaces).",
        )
        parser_group.add_argument(
            "--listen-port",
            dest="listen_port",
            type=int,
            help="Specifies the port on which SSH-MITM listens for incoming SSH connections. Ports ≤ 1024 require root privileges.",
        )
        parser_group.add_argument(
            "--transparent",
            dest="transparent",
            action="store_true",
            help="Enables transparent mode, which uses Linux TProxy for intercepting incoming connections. Requires root privileges.",
        )
        parser_group.add_argument(
            "--host-key-algorithms",
            dest="host_key_algorithms",
            nargs="*",
            metavar="ALGORITHM",
            help="List of host key algorithms to use. Accepted values: rsa, ecdsa, ed25519. Keys are loaded from or persisted to the state directory unless an explicit path is given via --host-key-rsa / --host-key-ecdsa / --host-key-ed25519.",
        )
        parser_group.add_argument(
            "--host-key-rsa",
            dest="host_key_rsa",
            metavar="FILE",
            help="Path to the RSA host key file. If the file does not exist, a new RSA key is generated and saved there.",
        )
        parser_group.add_argument(
            "--host-key-ecdsa",
            dest="host_key_ecdsa",
            metavar="FILE",
            help="Path to the ECDSA host key file. If the file does not exist, a new ECDSA key is generated and saved there.",
        )
        parser_group.add_argument(
            "--host-key-ed25519",
            dest="host_key_ed25519",
            metavar="FILE",
            help="Path to the Ed25519 host key file. If the file does not exist, a new Ed25519 key is generated and saved there.",
        )
        parser_group.add_argument(
            "--host-key-rsa-length",
            dest="host_key_rsa_length",
            type=int,
            help="Bit length for generated RSA host keys (default: 2048).",
        )
        parser_group.add_argument(
            "--banner-name",
            dest="banner_name",
            default=None,
            help="Sets a custom SSH server banner presented to clients during the initial connection. If not set, the remote server's banner is passed through. Default: remote server banner or ``SSH-2.0-SSHMITM_<version>`` as fallback.",
        )

        if self.module_parser is not None:
            self.parser.register_extra_parser(self.module_parser)
        self.parser.add_browser_argument("--plugins")

    def execute(self, args: argparse.Namespace) -> None:
        proxy = SSHProxyServer(
            args.listen_address,
            args.listen_port,
            key_algorithms=args.host_key_algorithms or [],
            key_file_rsa=args.host_key_rsa,
            key_file_ecdsa=args.host_key_ecdsa,
            key_file_ed25519=args.host_key_ed25519,
            key_rsa_length=args.host_key_rsa_length,
            ssh_interface=args.ssh_interface,
            scp_interface=args.scp_interface,
            netconf_interface=args.netconf_interface,
            powershell_interface=args.powershell_interface,
            sftp_interface=args.sftp_interface,
            sftp_handler=args.sftp_handler,
            server_tunnel_interface=args.server_tunnel_interface,
            client_tunnel_interface=args.client_tunnel_interface,
            authentication_interface=args.auth_interface,
            authenticator=args.authenticator,
            transparent=args.transparent,
            agent_forwarder=args.agent_forwarder,
            banner_name=args.banner_name,
            debug=args.debug,
        )
        proxy.print_serverinfo(args.log_format == "json")
        proxy.start()
