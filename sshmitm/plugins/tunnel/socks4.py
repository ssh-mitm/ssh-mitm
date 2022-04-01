import logging
from enum import Enum
import socket
from typing import (
    TYPE_CHECKING,
    cast,
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

import sshmitm
from sshmitm.forwarders.tunnel import TunnelForwarder, LocalPortForwardingForwarder
from sshmitm.plugins.session.tcpserver import TCPServerThread
if TYPE_CHECKING:
    from sshmitm.session import Session


class Socks4Error(Exception):
    pass


class Socks4Types(Enum):
    """Basisklasse für Socks4 Daten"""

    @typechecked
    def __str__(self) -> Text:
        return str(self.value)

    @typechecked
    def __add__(self, other: bytes) -> bytes:
        return cast(bytes, self.value) + other

    @typechecked
    def __radd__(self, other: bytes) -> bytes:
        return other + cast(bytes, self.value)


class Socks4Command(Socks4Types):
    """Kommandos für den Socks Proxy"""
    CONNECT = b"\x01"
    BIND = b"\x02"


class Socks4CommandReply(Socks4Types):
    """Bestättigungen für den Socks Proxy"""
    SUCCESS = b"\x5A"
    FAILED = b"\x5B"


class Socks4Server():
    """Socks4 kompatibler Forwarder
    """
    SOCKSVERSION = b"\x04"

    @typechecked
    def __init__(self, listenaddress: Tuple[Text, int]) -> None:
        self.listenaddress = listenaddress

    @property
    def server_ip(self) -> bytes:
        """Liefert die IP Adresse des Socks Proxy zurück"""
        return b"".join([bytes([int(i)]) for i in self.listenaddress[0].split(".")])

    @property
    def server_port(self) -> bytes:
        """Liefert den Port den Socks Proxy zurück"""
        server_port = self.listenaddress[1]
        return bytes([int(server_port / 256)]) + bytes([int(server_port % 256)])

    @typechecked
    def _get_address(self, clientsock: Union[socket.socket, paramiko.Channel]) -> Optional[Tuple[Text, int]]:
        """Ermittelt das Ziel aus der Socks Anfrage"""
        # get socks command
        try:
            command = Socks4Command(clientsock.recv(1))
        except ValueError:
            raise Socks4Error("Invalid Socks4 command")

        dst_addr_b: bytes
        dst_addr: Text
        dst_port_b: bytes
        dst_port: int

        dst_port_b, dst_addr_b = clientsock.recv(2), clientsock.recv(4)
        if len(dst_addr_b) != 4 or len(dst_port_b) != 2:
            raise Socks4Error("Invalid IPv4 Address")
        dst_addr = ".".join([str(i) for i in dst_addr_b])
        dst_port = dst_port_b[0] * 256 + dst_port_b[1]

        continue_recv = True
        userid = b""
        while continue_recv:
            nextchr = clientsock.recv(1)
            if nextchr == b"\x00":
                break
            userid += nextchr

        address: Optional[Tuple[Text, int]] = None
        reply = Socks4CommandReply.FAILED
        if command is Socks4Command.CONNECT:
            address = (dst_addr, dst_port)
            reply = Socks4CommandReply.SUCCESS

        clientsock.sendall(
            b"\x00" +
            reply +
            self.server_port +
            self.server_ip
        )
        return address

    @typechecked
    def get_address(self, clientsock: Union[socket.socket, paramiko.Channel], ignore_version: bool = False) -> Optional[Tuple[Text, int]]:
        try:
            # check socks version
            if not ignore_version and clientsock.recv(1) != Socks4Server.SOCKSVERSION:
                raise Socks4Error("Invalid Socks4 Version")
            return self._get_address(clientsock)
        except Socks4Error as sockserror:
            logging.error("Socks4 Error: %s", str(sockserror))
        return None


class ClientTunnelHandler:
    """
    Similar to the RemotePortForwardingForwarder
    """

    @typechecked
    def __init__(
        self,
        session: 'sshmitm.session.Session'
    ) -> None:
        self.session = session

    @typechecked
    def handle_request(self, listenaddr: Tuple[Text, int], client: Union[socket.socket, paramiko.Channel], addr: Optional[Tuple[str, int]]) -> None:
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            return
        destination: Optional[Tuple[Text, int]] = None
        Socks4connection = Socks4Server(listenaddr)
        destination = Socks4connection.get_address(client)
        if destination is None:
            client.close()
            logging.error("unable to parse Socks4 request")
            return
        try:
            logging.debug("Injecting direct-tcpip channel (%s -> %s) to client", addr, destination)
            remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", destination, addr)
            TunnelForwarder(client, remote_ch)
        except paramiko.ssh_exception.ChannelException:
            client.close()
            logging.error("Could not setup forward from %s to %s.", addr, destination)


class SOCKS4TunnelForwarder(LocalPortForwardingForwarder):
    """Serve out direct-tcpip connections over a session on local ports
    """

    @classmethod
    @typechecked
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
    @typechecked
    def setup(cls, session: 'sshmitm.session.Session') -> None:
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval

        t = TCPServerThread(
            ClientTunnelHandler(session).handle_request,
            run_status=session.running,
            network=args.socks_listen_address
        )
        t.start()
        cls.tcpservers.append(t)
        logging.info((
            f"{EMOJI['information']} {stylize(session.sessionid, fg('light_blue') + attr('bold'))}"
            " - "
            f"created Socks4 proxy server on port {stylize(t.port, fg('light_blue') + attr('bold'))}. "
            f"connect with {stylize(f'socat TCP-LISTEN:LISTEN_PORT,fork socks4:127.0.0.1:DESTINATION_ADDR:DESTINATION_PORT,socksport={t.port}', fg('light_blue') + attr('bold'))}"
        ))
