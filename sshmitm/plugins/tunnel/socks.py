import logging
import socket
from typing import (
    List,
    Optional,
    Tuple,
    Union
)

import paramiko
from rich._emoji_codes import EMOJI
from colored.colored import stylize, fg, attr  # type: ignore

import sshmitm
from sshmitm.forwarders.tunnel import TunnelForwarder, LocalPortForwardingForwarder
from sshmitm.plugins.session.tcpserver import TCPServerThread

from sshmitm.plugins.tunnel.socks4 import Socks4Server, Socks4Error
from sshmitm.plugins.tunnel.socks5 import Socks5Server, Socks5Error


class ClientTunnelHandler:
    """
    Similar to the RemotePortForwardingForwarder
    """

    def __init__(
        self,
        session: 'sshmitm.session.Session'
    ) -> None:
        self.session = session

    def handle_request(
        self, listenaddr: Tuple[str, int], client: Union[socket.socket, paramiko.Channel], addr: Optional[Tuple[str, int]]
    ) -> None:
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            return
        destination: Optional[Tuple[str, int]] = None
        socksconnection: Optional[Union[Socks4Server, Socks5Server]] = None
        try:
            socksversion = client.recv(1)
            if socksversion == Socks4Server.SOCKSVERSION:
                socksconnection = Socks4Server(listenaddr)
                destination = socksconnection.get_address(client, ignore_version=True)
            elif socksversion == Socks5Server.SOCKSVERSION:
                socksconnection = Socks5Server(listenaddr)
                destination = socksconnection.get_address(client, ignore_version=True)
        except (Socks4Error, Socks5Error) as sockserror:
            logging.error('unable to parse SOCKS request! %s', sockserror)
        if destination is None:
            client.close()
            logging.error("unable to parse SOCKS request")
            return
        try:
            logging.debug("Injecting direct-tcpip channel (%s -> %s) to client", addr, destination)
            remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", destination, addr)
            TunnelForwarder(client, remote_ch)
        except paramiko.ssh_exception.ChannelException:
            client.close()
            logging.error("Could not setup forward from %s to %s.", addr, destination)


class SOCKSTunnelForwarder(LocalPortForwardingForwarder):
    """Serve out direct-tcpip connections over a session on local ports
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--socks-listen-address',
            dest='socks_listen_address',
            default='127.0.0.1',
            help='socks server listen address (default: 127.0.0.1)'
        )

    tcpservers: List[TCPServerThread] = []

    # Setup should occur after master channel establishment

    @classmethod
    def setup(cls, session: 'sshmitm.session.Session') -> None:
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval

        server_thread = TCPServerThread(
            ClientTunnelHandler(session).handle_request,
            run_status=session.running,
            network=args.socks_listen_address
        )
        server_thread.start()
        cls.tcpservers.append(server_thread)

        socat_cmd = f'socat TCP-LISTEN:LISTEN_PORT,fork socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport={server_thread.port}'
        netcat4_cmd = f'nc -X 4 -x localhost:{server_thread.port} address port'
        netcat5_cmd = f'nc -X 5 -x localhost:{server_thread.port} address port'

        logging.info(
            (
                "%s %s - local port forwading\n"
                "%s %s\n"
                "  %s\n"
                "    * socat: %s\n"
                "    * netcat: %s\n"
                "  %s\n"
                "    * netcat: %s"
            ),
            EMOJI['information'],
            stylize(session.sessionid, fg('light_blue') + attr('bold')),
            stylize('SOCKS port:', attr('bold')),
            stylize(server_thread.port, fg('light_blue') + attr('bold')),
            stylize('SOCKS4:', attr('bold')),
            stylize(socat_cmd, fg('light_blue') + attr('bold')),
            stylize(netcat4_cmd, fg('light_blue') + attr('bold')),
            stylize('SOCKS5:', attr('bold')),
            stylize(netcat5_cmd, fg('light_blue') + attr('bold'))
        )
