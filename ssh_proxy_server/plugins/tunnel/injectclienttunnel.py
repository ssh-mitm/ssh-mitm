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

import ssh_proxy_server
from ssh_proxy_server.forwarders.tunnel import TunnelForwarder, ClientTunnelForwarder
from ssh_proxy_server.plugins.session.tcpserver import TCPServerThread
if TYPE_CHECKING:
    from ssh_proxy_server.session import Session

class ClientTunnelHandler:
    """
    Similar to the ServerTunnelForwarder
    """

    @typechecked
    def __init__(
        self,
        session: 'ssh_proxy_server.session.Session',
        destination: Optional[Tuple[str, int]]
    ) -> None:
        self.session = session
        self.destination = destination

    @typechecked
    def handle_request(self, client: Union[socket.socket, paramiko.Channel], addr: Optional[Tuple[str, int]]) -> None:
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            return
        try:
            logging.debug("Injecting direct-tcpip channel (%s -> %s) to client", addr, self.destination)
            remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", self.destination, addr)
            TunnelForwarder(client, remote_ch)
        except paramiko.ssh_exception.ChannelException:
            client.close()
            logging.error("Could not setup forward from %s to %s.", addr, self.destination)


class InjectableClientTunnelForwarder(ClientTunnelForwarder):
    """Serve out direct-tcpip connections over a session on local ports
    """

    @classmethod
    @typechecked
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--tunnel-client-dest',
            dest='client_tunnel_dest',
            help='multiple direct-tcpip address/port combination to forward to (e.g. google.com:80, youtube.com:80)',
            required=True,
            nargs='+'
        )
        plugin_group.add_argument(
            '--tunnel-client-net',
            dest='client_tunnel_net',
            default='127.0.0.1',
            help='network on which to serve the client tunnel injector'
        )

    session: Optional['ssh_proxy_server.session.Session'] = None
    args: Optional[argparse.Namespace] = None
    tcpservers: List[TCPServerThread] = []

    # Setup should occur after master channel establishment

    @classmethod
    @typechecked
    def setup(cls, session: 'ssh_proxy_server.session.Session') -> None:
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval
        cls.session = session
        cls.args = args
        form = re.compile('.*:\d{1,5}')

        for target in cls.args.client_tunnel_dest:
            if not form.match(target):
                logging.warning("--tunnel-client-dest %s does not match format host:port (e.g. google.com:80)", target)
                break
            destnet, destport = target.split(":")
            t = TCPServerThread(
                ClientTunnelHandler(session, (destnet, int(destport))).handle_request,
                run_status=cls.session.running,
                network=cls.args.client_tunnel_net
            )
            t.start()
            cls.tcpservers.append(t)
            logging.info(
                f"{session} created client tunnel injector for host {t.network} on port {t.port} to destination {target}"
            )
