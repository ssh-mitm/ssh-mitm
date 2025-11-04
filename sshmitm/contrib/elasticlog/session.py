import socket
from typing import TYPE_CHECKING, Optional, Tuple, Type, Union

from sshmitm.contrib.elasticlog.log_collection import LogForwarder
from sshmitm.core.session import Session

if TYPE_CHECKING:

    import sshmitm
    from sshmitm.core.server import SSHProxyServer  # noqa: F401


class ElasticlogSession(Session):
    """Session Class, SSH commands and responses to a remote HTTP server (e.g. elastic) for log collection and analyzation"""

    @classmethod
    def parser_arguments(cls) -> None:
        """
        Add an argument to the command line parser for session plugin.
        """
        super().parser_arguments()
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--log-webhook-dest",
            dest="log_webhook_dest",
            help="Transmits SSH commands and responses to a remote HTTP server for log collection and analyzation",
        )

    def __init__(  # pylint: disable=too-many-arguments
        self,
        proxyserver: "sshmitm.core.server.SSHProxyServer",
        client_socket: socket.socket,
        client_address: Union[Tuple[str, int], Tuple[str, int, int, int]],
        authenticator: Type["sshmitm.core.authentication.Authenticator"],
        remoteaddr: Union[Tuple[str, int], Tuple[str, int, int, int]],
        banner_name: Optional[str] = None,
    ) -> None:
        super().__init__(
            proxyserver,
            client_socket,
            client_address,
            authenticator,
            remoteaddr,
            banner_name,
        )
        self.log_forwarder = LogForwarder(
            client_ip=self.client_address[0],
            client_port=self.client_address[1],
            server_ip=self.socket_remote_address[0],
            server_port=self.socket_remote_address[1],
            log_webhook_dest=self.args.log_webhook_dest,
        )

    def start(self) -> bool:
        start_result = super().start()

        # Username and password become available after authentication
        self.log_forwarder.set_credentials(self.username, self.password)
        self.log_forwarder.set_cipher(self.transport.remote_cipher)
        # Set ssh transport metadata
        self.log_forwarder.set_server_transport_metadata(
            server_extensions=self.ssh_client.transport.server_extensions,
            proto_version=self.ssh_client.transport.remote_version.split("-", 3)[1],
            software_version=self.ssh_client.transport.remote_version.split("-", 3)[2],
            preferred_ciphers=self.ssh_client.transport.preferred_ciphers,
            preferred_kex=self.ssh_client.transport.preferred_kex,
            preferred_macs=self.ssh_client.transport.preferred_macs,
            preferred_compression=self.ssh_client.transport.preferred_compression,
        )
        self.log_forwarder.set_client_transport_metadata(
            server_extensions=self.transport.server_extensions,
            proto_version=self.transport.remote_version.split("-", 3)[1],
            software_version=self.transport.remote_version.split("-", 3)[2],
            preferred_ciphers=self.transport.preferred_ciphers,
            preferred_kex=self.transport.preferred_kex,
            preferred_macs=self.transport.preferred_macs,
            preferred_compression=self.transport.preferred_compression,
        )

        return start_result
