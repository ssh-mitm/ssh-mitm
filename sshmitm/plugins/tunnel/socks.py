import logging
import socket
import sys
from typing import TYPE_CHECKING, ClassVar, List, Optional, Tuple, Union

import paramiko
from colored.colored import attr, fg  # type: ignore[import-untyped]

from sshmitm.forwarders.tunnel import (
    BaseClientTunnelHandler,
    LocalPortForwardingForwarder,
    TunnelForwarder,
)
from sshmitm.logging import Colors
from sshmitm.plugins.session.tcpserver import TCPServerThread
from sshmitm.plugins.tunnel.socks4 import Socks4Error, Socks4Server
from sshmitm.plugins.tunnel.socks5 import Socks5Error, Socks5Server

if TYPE_CHECKING:
    import sshmitm


class ClientTunnelHandler(BaseClientTunnelHandler):
    """
    Similar to the RemotePortForwardingForwarder
    """

    def __init__(
        self,
        session: "sshmitm.session.Session",
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        super().__init__(session)
        self.username = username
        self.password = password

    def handle_request(
        self,
        listenaddr: Tuple[str, int],
        client: Union[socket.socket, paramiko.Channel],
        addr: Optional[Tuple[str, int]],
    ) -> None:
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            return
        destination: Optional[Tuple[str, int]] = None
        socksconnection: Optional[Union[Socks4Server, Socks5Server]] = None
        try:
            socksversion = client.recv(1)
            if socksversion == Socks4Server.SOCKSVERSION:
                if self.username or self.password:
                    logging.error(
                        "client tied to connect with SOCKS4 but authentication is enaled!"
                    )
                    return
                socksconnection = Socks4Server(listenaddr)
                destination = socksconnection.get_address(client, ignore_version=True)
            elif socksversion == Socks5Server.SOCKSVERSION:
                socksconnection = Socks5Server(listenaddr, self.username, self.password)
                destination = socksconnection.get_address(client, ignore_version=True)
        except (Socks4Error, Socks5Error) as sockserror:
            logging.error("unable to parse SOCKS request! %s", sockserror)
        if destination is None:
            client.close()
            logging.error("unable to parse SOCKS request")
            return
        try:
            logging.debug(
                "Injecting direct-tcpip channel (%s -> %s) to client", addr, destination
            )
            remote_ch = self.session.ssh_client.transport.open_channel(
                "direct-tcpip", destination, addr
            )
            TunnelForwarder(client, remote_ch)
        except paramiko.ssh_exception.ChannelException:
            client.close()
            logging.error("Could not setup forward from %s to %s.", addr, destination)


class SOCKSTunnelForwarder(LocalPortForwardingForwarder):
    """SOCKS4/5 server to serve out direct-tcpip connections over a session on local ports"""

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--socks-listen-address",
            dest="socks_listen_address",
            help="socks server listen address (default: 127.0.0.1)",
        )
        plugin_group.add_argument(
            "--socks5-username",
            dest="socks5_username",
            help="username for the SOCKS5 server",
        )
        plugin_group.add_argument(
            "--socks5-password",
            dest="socks5_password",
            required="--socks5-username" in sys.argv,
            help="password for the SOCKS5 server",
        )

    tcpservers: ClassVar[List[TCPServerThread]] = []

    # Setup should occur after master channel establishment

    @classmethod
    def setup(cls, session: "sshmitm.session.Session") -> None:
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval

        server_thread = TCPServerThread(
            ClientTunnelHandler(
                session, args.socks5_username, args.socks5_password
            ).handle_request,
            run_status=session.running,
            network=args.socks_listen_address,
        )
        server_thread.start()
        cls.tcpservers.append(server_thread)

        socat_cmd = f"socat TCP-LISTEN:LISTEN_PORT,fork socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport={server_thread.port}"
        netcat4_cmd = f"nc -X 4 -x localhost:{server_thread.port} address port"
        netcat5_cmd = f"nc -X 5 -x localhost:{server_thread.port} address port"

        logging.info(
            (
                "%s %s - local port forwarding\n"
                "%s %s\n"
                "  %s\n"
                "    * socat: %s\n"
                "    * netcat: %s\n"
                "  %s\n"
                "    * netcat: %s"
            ),
            Colors.emoji("information"),
            Colors.stylize(session.sessionid, fg("light_blue") + attr("bold")),
            Colors.stylize("SOCKS port:", attr("bold")),
            Colors.stylize(server_thread.port, fg("light_blue") + attr("bold")),
            Colors.stylize("SOCKS4:", attr("bold")),
            Colors.stylize(socat_cmd, fg("light_blue") + attr("bold")),
            Colors.stylize(netcat4_cmd, fg("light_blue") + attr("bold")),
            Colors.stylize("SOCKS5:", attr("bold")),
            Colors.stylize(netcat5_cmd, fg("light_blue") + attr("bold")),
        )
