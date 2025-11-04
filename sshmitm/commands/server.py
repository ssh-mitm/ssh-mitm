import argparse
from typing import Optional

from sshmitm import __version__ as ssh_mitm_version
from sshmitm import project_metadata
from sshmitm.core.authentication import Authenticator
from sshmitm.core.forwarders.scp import SCPBaseForwarder
from sshmitm.core.forwarders.sftp import SFTPHandlerBasePlugin
from sshmitm.core.forwarders.ssh import SSHBaseForwarder
from sshmitm.core.forwarders.tunnel import (
    LocalPortForwardingBaseForwarder,
    RemotePortForwardingBaseForwarder,
)
from sshmitm.core.interfaces.server import BaseServerInterface
from sshmitm.core.interfaces.sftp import BaseSFTPServerInterface
from sshmitm.core.server import SSHProxyServer
from sshmitm.core.session import BaseSession
from sshmitm.moduleparser import SubCommand


class SSHServerModules(SubCommand):
    """start the ssh-mitm server"""

    @classmethod
    def config_section(cls) -> Optional[str]:
        return "SSH-Server-Modules"

    def register_arguments(self) -> None:
        self.parser.add_module(
            "--ssh-interface",
            dest="ssh_interface",
            help="Specifies the interface responsible for managing SSH terminal sessions, including shell interaction and command execution.",
            baseclass=SSHBaseForwarder,
        )
        self.parser.add_module(
            "--scp-interface",
            dest="scp_interface",
            help="Defines the interface used for handling SCP (Secure Copy Protocol) file transfers, including uploads and downloads.",
            baseclass=SCPBaseForwarder,
        )
        self.parser.add_module(
            "--sftp-interface",
            dest="sftp_interface",
            help="Sets the base interface for SFTP (SSH File Transfer Protocol) operations, such as file listing, uploads, and downloads.",
            baseclass=BaseSFTPServerInterface,
        )
        self.parser.add_module(
            "--sftp-handler",
            dest="sftp_handler",
            help="Specifies the handler for SFTP operations, responsible for processing file transfer requests and managing file system interactions.",
            baseclass=SFTPHandlerBasePlugin,
        )
        self.parser.add_module(
            "--remote-port-forwarder",
            dest="server_tunnel_interface",
            help="Configures the interface for managing server-side tunnel operations, such as remote port forwarding.",
            baseclass=RemotePortForwardingBaseForwarder,
        )
        self.parser.add_module(
            "--local-port-forwarder",
            dest="client_tunnel_interface",
            help="Sets the interface for handling client-side tunnel operations, such as local port forwarding.",
            baseclass=LocalPortForwardingBaseForwarder,
        )
        self.parser.add_module(
            "--auth-interface",
            dest="auth_interface",
            help="Defines the interface responsible for authentication processes, including credential validation and session initialization.",
            baseclass=BaseServerInterface,
        )
        self.parser.add_module(
            "--authenticator",
            dest="authenticator",
            help="Specifies the authenticator module used for validating user credentials and managing authentication workflows.",
            baseclass=Authenticator,
        )
        self.parser.add_module(
            "--session-class",
            dest="session_class",
            help=f"Sets the custom session class for {project_metadata.PROJECT_NAME}, controlling session behavior, logging, and interaction handling.",
            baseclass=BaseSession,
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
            help=f"Specifies the port on which {project_metadata.PROJECT_NAME} listens for incoming SSH connections. Ports ≤ 1024 require root privileges.",
        )
        parser_group.add_argument(
            "--transparent",
            dest="transparent",
            action="store_true",
            help="Enables transparent mode, which uses Linux TProxy for intercepting incoming connections. Requires root privileges.",
        )
        parser_group.add_argument(
            "--host-key",
            dest="host_key",
            help="Specifies the path to a custom private SSH key used as the host key. If not provided, a random host key is generated.",
        )
        parser_group.add_argument(
            "--host-key-algorithm",
            dest="host_key_algorithm",
            choices=["dss", "rsa", "ecdsa", "ed25519"],
            help="Defines the algorithm used to generate the random host key (default: `rsa`).",
        )
        parser_group.add_argument(
            "--host-key-length",
            dest="host_key_length",
            type=int,
            help="Sets the key length for the generated host key (applies to `dss` and `rsa` algorithms, default: `2048`).",
        )
        parser_group.add_argument(
            "--banner-name",
            dest="banner_name",
            default=f"SSHMITM_{ssh_mitm_version}",
            help="Sets a custom SSH server banner presented to clients during the initial connection. Default: ``SSH-2.0-SSHMITM_<version>``.",
        )
        parser_group.add_argument(
            "--log-webhook-dest",
            dest="log_webhook_dest",
            help="Transmits SSH commands and responses to a remote HTTP server for log collection and analyzation",
        )

    def execute(self, args: argparse.Namespace) -> None:
        proxy = SSHProxyServer(
            args.listen_address,
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
            debug=args.debug,
            log_webhook_dest=args.log_webhook_dest,
        )
        proxy.print_serverinfo(args.log_format == "json")
        proxy.start()
