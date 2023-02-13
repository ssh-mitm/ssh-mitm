import logging
from enum import Enum
import socket
import sys
from typing import (
    cast,
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


class Socks5Error(Exception):
    pass


class Socks5Types(Enum):
    """Basisklasse für Socks5 Daten"""

    def __str__(self) -> str:
        return str(self.value)

    def __add__(self, other: bytes) -> bytes:
        return cast(bytes, self.value) + other

    def __radd__(self, other: bytes) -> bytes:
        return other + cast(bytes, self.value)


class Socks5AuthenticationType(Socks5Types):
    """Authentifizierungstypen für den Socks Proxy"""
    NONE = b"\x00"
    PASSWORD = b"\x02"


class Socks5Command(Socks5Types):
    """Kommandos für den Socks Proxy"""
    CONNECT = b"\x01"
    BIND = b"\x02"
    UDP = b"\x03"


class Socks5AddressType(Socks5Types):
    """Addresstypen für den Socks Proxy"""
    IPv4 = b"\x01"  # pylint: disable=invalid-name
    DOMAIN = b"\x03"
    IPv6 = b"\x04"  # pylint: disable=invalid-name


class Socks5CommandReply(Socks5Types):
    """Bestättigungen für den Socks Proxy"""
    SUCCESS = b"\x00"
    GENERAL_FAILURE = b"\x01"
    CONNECTION_NOT_ALLOWED = b"\x02"
    NETWORK_UNREACHABLE = b"\x03"
    HOST_UNREACHABLE = b"\x04"
    CONNECTION_REFUSED = b"\x05"
    TTL_EXPIRED = b"\x06"
    COMMAND_NOT_SUPPORTED = b"\x07"
    ADDR_TYPE_NOT_SUPPORTED = b"\x00"


class Socks5Server():
    """Socks5 kompatibler Forwarder
    Dieser Socks5 Forwarder unterstützt Authentifizierung.
    """
    SOCKSVERSION = b"\x05"
    AUTH_PASSWORD_VERSION = b"\x01"

    def __init__(
        self, listenaddress: Tuple[str, int], username: Optional[str] = None, password: Optional[str] = None
    ) -> None:
        self.listenaddress = listenaddress
        self.username: Optional[str] = username
        self.password: Optional[str] = password
        self.auth_required: bool = self.username is not None and self.password is not None

    @property
    def server_ip(self) -> bytes:
        """Liefert die IP Adresse des Socks Proxy zurück"""
        return b"".join([bytes([int(i)]) for i in self.listenaddress[0].split(".")])

    @property
    def server_port(self) -> bytes:
        """Liefert den Port den Socks Proxy zurück"""
        server_port = self.listenaddress[1]
        return bytes([int(server_port / 256)]) + bytes([int(server_port % 256)])

    def _get_auth_methods(self, clientsock: Union[socket.socket, paramiko.Channel]) -> List[Socks5AuthenticationType]:
        """Ermittelt die angebotenen Authentifizierungsmechanismen"""
        methods_count = int.from_bytes(clientsock.recv(1), byteorder='big')
        try:
            methods = [Socks5AuthenticationType(bytes([m])) for m in clientsock.recv(methods_count)]
        except ValueError as exc:
            raise Socks5Error("Invalid methods") from exc
        if len(methods) != methods_count:
            raise Socks5Error("Invalid number of methods")
        return methods

    def _authenticate(self, clientsock: Union[socket.socket, paramiko.Channel]) -> bool:
        """Authentifiziert den Benutzer"""
        authmethods = self._get_auth_methods(clientsock)

        if not self.auth_required and Socks5AuthenticationType.NONE in authmethods:
            clientsock.sendall(Socks5Server.SOCKSVERSION + Socks5AuthenticationType.NONE)
            return True
        if self.auth_required and Socks5AuthenticationType.PASSWORD in authmethods:
            clientsock.sendall(Socks5Server.SOCKSVERSION + Socks5AuthenticationType.PASSWORD)
        else:
            clientsock.sendall(Socks5Server.SOCKSVERSION + b"\xFF")
            logging.warning("client does not offer supported authentication types")
            return False

        if Socks5Server.AUTH_PASSWORD_VERSION != clientsock.recv(1):
            raise Socks5Error('Wrong Authentication Version')

        username_len: int = int.from_bytes(clientsock.recv(1), byteorder='big')
        username: str = clientsock.recv(username_len).decode("utf8")
        if len(username) != username_len:
            raise Socks5Error("Invalid username length")

        password_len: int = int.from_bytes(clientsock.recv(1), byteorder='big')
        password: str = clientsock.recv(password_len).decode("utf8")
        if len(password) != password_len:
            raise Socks5Error("Invalid password length")

        if self.check_credentials(username, password):
            clientsock.sendall(Socks5Server.AUTH_PASSWORD_VERSION + b"\x00")
            return True

        logging.warning("Authentication failed")
        clientsock.sendall(Socks5Server.AUTH_PASSWORD_VERSION + b"\x01")
        return False

    def _get_address(self, clientsock: Union[socket.socket, paramiko.Channel]) -> Optional[Tuple[str, int]]:
        """Ermittelt das Ziel aus der Socks Anfrage"""
        # check socks version
        if clientsock.recv(1) != Socks5Server.SOCKSVERSION:
            raise Socks5Error("Invalid Socks5 Version")
        # get socks command
        try:
            command = Socks5Command(clientsock.recv(1))
        except ValueError as exc:
            raise Socks5Error("Invalid Socks5 command") from exc

        if clientsock.recv(1) != b"\x00":
            raise Socks5Error("Reserved byte must be 0x00")

        try:
            address_type: Socks5AddressType = Socks5AddressType(clientsock.recv(1))
        except ValueError as exc:
            raise Socks5Error("Invalid Socks5 address type") from exc

        dst_addr_b: bytes
        dst_addr: str
        dst_port_b: bytes
        dst_port: int

        if address_type is Socks5AddressType.IPv4:
            dst_addr_b, dst_port_b = clientsock.recv(4), clientsock.recv(2)
            if len(dst_addr_b) != 4 or len(dst_port_b) != 2:
                raise Socks5Error("Invalid IPv4 Address")
            dst_addr = ".".join([str(i) for i in dst_addr_b])
        elif address_type is Socks5AddressType.DOMAIN:
            addr_len = int.from_bytes(clientsock.recv(1), byteorder='big')
            dst_addr_b, dst_port_b = clientsock.recv(addr_len), clientsock.recv(2)
            if len(dst_addr_b) != addr_len or len(dst_port_b) != 2:
                raise Socks5Error("Invalid domain")
            dst_addr = "".join([chr(i) for i in dst_addr_b])
        elif address_type is Socks5AddressType.IPv6:
            dst_addr_b, dst_port_b = clientsock.recv(16), clientsock.recv(2)
            if len(dst_addr_b) != 16 or len(dst_port_b) != 2:
                raise Socks5Error("Invalid IPv6 Address")
            tmp_addr = []
            for i in range(int(len(dst_addr_b) / 2)):
                tmp_addr.append(chr(dst_addr_b[2 * i] * 256 + dst_addr_b[2 * i + 1]))
            dst_addr = ":".join(tmp_addr)
        else:
            raise Socks5Error("Unhandled address type")

        dst_port = dst_port_b[0] * 256 + dst_port_b[1]

        address: Optional[Tuple[str, int]] = None
        reply = Socks5CommandReply.COMMAND_NOT_SUPPORTED
        if command is Socks5Command.CONNECT:
            address = (dst_addr, dst_port)
            reply = Socks5CommandReply.SUCCESS

        clientsock.sendall(
            Socks5Server.SOCKSVERSION +
            reply +
            b"\x00" +
            Socks5AddressType.IPv4 +
            self.server_ip +
            self.server_port
        )
        return address

    def check_credentials(self, username: str, password: str) -> bool:
        """Prüft Benutzername und Passwort"""
        return username == self.username and password == self.password

    def get_address(
        self, clientsock: Union[socket.socket, paramiko.Channel], ignore_version: bool = False
    ) -> Optional[Tuple[str, int]]:
        try:
            # check socks version
            if not ignore_version and clientsock.recv(1) != Socks5Server.SOCKSVERSION:
                raise Socks5Error("Invalid Socks5 Version")
            if self._authenticate(clientsock):
                return self._get_address(clientsock)
        except Socks5Error as sockserror:
            logging.error("Socks5 Error: %s", str(sockserror))
        return None


class ClientTunnelHandler:
    """
    Similar to the RemotePortForwardingForwarder
    """

    def __init__(
        self,
        session: 'sshmitm.session.Session',
        username: Optional[str] = None,
        password: Optional[str] = None
    ) -> None:
        self.session = session
        self.username = username
        self.password = password

    def handle_request(
        self, listenaddr: Tuple[str, int], client: Union[socket.socket, paramiko.Channel], addr: Optional[Tuple[str, int]]
    ) -> None:
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            return
        destination: Optional[Tuple[str, int]] = None
        socks5connection = Socks5Server(listenaddr, self.username, self.password)
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
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--socks-listen-address',
            dest='socks_listen_address',
            default='127.0.0.1',
            help='socks server listen address (default: 127.0.0.1)'
        )
        plugin_group.add_argument(
            '--socks5-username',
            dest='socks5_username',
            help='username for the SOCKS5 server'
        )
        plugin_group.add_argument(
            '--socks5-password',
            dest='socks5_password',
            required='--socks5-username' in sys.argv,
            help='password for the SOCKS5 server'
        )

    tcpservers: List[TCPServerThread] = []

    # Setup should occur after master channel establishment

    @classmethod
    def setup(cls, session: 'sshmitm.session.Session') -> None:
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval

        serverthread = TCPServerThread(
            ClientTunnelHandler(session, args.socks5_username, args.socks5_password).handle_request,
            run_status=session.running,
            network=args.socks_listen_address
        )
        serverthread.start()
        cls.tcpservers.append(serverthread)
        logging.info(
            "%s %s - created SOCKS5 proxy server on port %s. connect with: %s",
            EMOJI['information'],
            stylize(session.sessionid, fg('light_blue') + attr('bold')),
            serverthread.port,
            stylize(f'nc -X 5 -x localhost:{serverthread.port} address port', fg('light_blue') + attr('bold'))
        )
