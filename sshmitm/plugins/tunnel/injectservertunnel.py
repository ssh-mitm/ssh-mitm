import logging
from socket import socket
from typing import TYPE_CHECKING, Optional, Tuple, Union

import paramiko
from colored.colored import attr, fg  # type: ignore[import-untyped]

from sshmitm.forwarders.tunnel import RemotePortForwardingForwarder, TunnelForwarder
from sshmitm.logging import Colors
from sshmitm.plugins.session.tcpserver import TCPServerThread

if TYPE_CHECKING:
    import sshmitm


class InjectableRemotePortForwardingForwarder(RemotePortForwardingForwarder):
    """For each server port forwarding request open a local port to inject traffic into the port-forward

    The Handler is still the same as the RemotePortForwardingForwarder, only a tcp server is added

    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--tunnel-server-net",
            dest="server_tunnel_net",
            help="local address/interface where injector sessions are served",
        )

    def __init__(
        self,
        session: "sshmitm.session.Session",
        server_interface: "sshmitm.interfaces.server.ServerInterface",
        destination: Optional[Tuple[str, int]],
    ) -> None:
        super().__init__(session, server_interface, destination)
        self.tcpserver = TCPServerThread(
            self.handle_request,
            network=self.args.server_tunnel_net,
            run_status=self.session.running,
        )
        logging.info(
            "%s %s - created server tunnel injector for host %s on port %s to destination %s",
            Colors.emoji("information"),
            Colors.stylize(session.sessionid, fg("light_blue") + attr("bold")),
            self.tcpserver.network,
            self.tcpserver.port,
            self.destination,
        )
        self.tcpserver.start()

    def handle_request(
        self,
        listenaddr: Tuple[str, int],
        client: Union[socket, paramiko.Channel],
        addr: Tuple[str, int],
    ) -> None:
        del listenaddr  # unused arguments
        try:
            forwarded_tunnel = TunnelForwarder(
                self.session.transport.open_channel(
                    "forwarded-tcpip", self.destination, addr
                ),
                client,
            )
            self.server_interface.forwarders.append(forwarded_tunnel)
        except (paramiko.SSHException, OSError):
            logging.warning(
                "portforward - injector connection suffered an unexpected error"
            )
            self.tcpserver.close()
