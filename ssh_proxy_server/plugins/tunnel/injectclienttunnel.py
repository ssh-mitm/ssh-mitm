import logging
import argparse
import re
import socket
from typing import (
    TYPE_CHECKING,
    List,
    Optional,
    Tuple,
    Union,
    Text
)

import paramiko
from typeguard import typechecked
from rich._emoji_codes import EMOJI
from colored.colored import stylize, fg, attr  # type: ignore

import ssh_proxy_server
from ssh_proxy_server.forwarders.tunnel import TunnelForwarder, LocalPortForwardingForwarder
from ssh_proxy_server.plugins.session.tcpserver import TCPServerThread
from ssh_proxy_server.socks.server import Socks5Server  # type: ignore
if TYPE_CHECKING:
    from ssh_proxy_server.session import Session

class ClientTunnelHandler:
    """
    Similar to the RemotePortForwardingForwarder
    """

    @typechecked
    def __init__(
        self,
        session: 'ssh_proxy_server.session.Session'
    ) -> None:
        self.session = session

    @typechecked
    def handle_request(self, listenaddr: Tuple[Text, int], client: Union[socket.socket, paramiko.Channel], addr: Optional[Tuple[str, int]]) -> None:
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            return
        destination: Optional[Tuple[Text, int]] = None
        socks5connection = Socks5Server(listenaddr)
        destination = socks5connection.get_address(client)
        if destination is None:
            client.close()
            logging.error("unable to parse socks5 request")
            return
        try:
            logging.debug("Injecting direct-tcpip channel (%s -> %s) to client", addr, destination)
            remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", destination, addr)
            TunnelForwarder(client, remote_ch)
        except paramiko.ssh_exception.ChannelException:
            client.close()
            logging.error("Could not setup forward from %s to %s.", addr, destination)


class SOCKS5TunnelForwarder(LocalPortForwardingForwarder):
    """Serve out direct-tcpip connections over a session on local ports
    """

    @classmethod
    @typechecked
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--tunnel-client-net',
            dest='client_tunnel_net',
            default='127.0.0.1',
            help='network on which to serve the client tunnel injector'
        )

    tcpservers: List[TCPServerThread] = []

    # Setup should occur after master channel establishment

    @classmethod
    @typechecked
    def setup(cls, session: 'ssh_proxy_server.session.Session') -> None:
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval

        t = TCPServerThread(
            ClientTunnelHandler(session).handle_request,
            run_status=session.running,
            network=args.client_tunnel_net
        )
        t.start()
        cls.tcpservers.append(t)
        logging.info((
            f"{EMOJI['information']} {stylize(session.sessionid, fg('light_blue') + attr('bold'))}"
            " - "
            f"created SOCKS5 proxy server on port {t.port}. connect with: {stylize(f'nc -X 5 -x localhost:{t.port} address port', fg('light_blue') + attr('bold'))}"
        ))
