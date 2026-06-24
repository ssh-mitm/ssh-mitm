import logging
from socket import socket
from typing import TYPE_CHECKING

import paramiko
from colored.colored import attr, fg

from sshmitm.forwarders.tunnel import RemotePortForwardingForwarder, TunnelForwarder
from sshmitm.moduleparser.colors import Colors
from sshmitm.plugins.session.tcpserver import TCPServerThread

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.interfaces.server import ServerInterface


class InjectableRemotePortForwardingForwarder(RemotePortForwardingForwarder):
    """Intercepts SSH remote port forwarding and opens a local injection port per session.

    When the SSH client requests remote port forwarding (``-R``), this plugin accepts
    the forwarded connection as usual and additionally starts a local TCP listener on
    a random port.  A second client can connect to that local port and have its traffic
    injected directly into the forwarded channel.

    SSH-MITM logs the injection port when the forwarding session is established::

        [i] <session-id> - created server tunnel injector for host 127.0.0.1 on port 34567 to destination ('10.0.0.1', 8080)

    **Usage example**

    ::

        ssh-mitm server --remote-port-forwarder inject

    Connect to the printed injection port to send data into the tunnel::

        nc 127.0.0.1 34567

    **Notes**

    * One injection listener is created per forwarded-tcpip channel.
    * Use ``--tunnel-server-net`` to bind the injection listener to a specific
      interface (default: all interfaces).
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--tunnel-server-net",
            dest="server_tunnel_net",
            help="Specifies the local address or network interface where tunnel server sessions are served.",
        )

    def __init__(
        self,
        session: "sshmitm.session.Session",
        server_interface: "ServerInterface",
        destination: tuple[str, int] | None,
    ) -> None:
        """Starts the local injection TCP listener for this forwarding session.

        :param session: the active SSH session being intercepted.
        :param server_interface: the paramiko server interface handling this session.
        :param destination: the remote host and port the client is forwarding to.
        """
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
        listenaddr: tuple[str, int],
        client: socket | paramiko.Channel,
        addr: tuple[str, int],
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
