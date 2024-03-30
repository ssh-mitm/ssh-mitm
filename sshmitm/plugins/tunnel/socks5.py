import logging
import socket
from enum import Enum
from typing import List, Optional, Tuple, Union, cast

import paramiko


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


class Socks5Server:
    """Socks5 kompatibler Forwarder
    Dieser Socks5 Forwarder unterstützt Authentifizierung.
    """

    SOCKSVERSION = b"\x05"
    AUTH_PASSWORD_VERSION = b"\x01"

    def __init__(
        self,
        listenaddress: Tuple[str, int],
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        self.listenaddress = listenaddress
        self.username: Optional[str] = username
        self.password: Optional[str] = password
        self.auth_required: bool = (
            self.username is not None and self.password is not None
        )

    @property
    def server_ip(self) -> bytes:
        """Liefert die IP Adresse des Socks Proxy zurück"""
        return b"".join([bytes([int(i)]) for i in self.listenaddress[0].split(".")])

    @property
    def server_port(self) -> bytes:
        """Liefert den Port den Socks Proxy zurück"""
        server_port = self.listenaddress[1]
        return bytes([int(server_port / 256)]) + bytes([int(server_port % 256)])

    def _get_auth_methods(
        self, clientsock: Union[socket.socket, paramiko.Channel]
    ) -> List[Socks5AuthenticationType]:
        """Ermittelt die angebotenen Authentifizierungsmechanismen"""
        methods_count = int.from_bytes(clientsock.recv(1), byteorder="big")
        try:
            methods = [
                Socks5AuthenticationType(bytes([m]))
                for m in clientsock.recv(methods_count)
            ]
        except ValueError as exc:
            msg = "Invalid methods"
            raise Socks5Error(msg) from exc
        if len(methods) != methods_count:
            msg = "Invalid number of methods"
            raise Socks5Error(msg)
        return methods

    def _authenticate(self, clientsock: Union[socket.socket, paramiko.Channel]) -> bool:
        """Authentifiziert den Benutzer"""
        authmethods = self._get_auth_methods(clientsock)

        if not self.auth_required and Socks5AuthenticationType.NONE in authmethods:
            clientsock.sendall(
                Socks5Server.SOCKSVERSION + Socks5AuthenticationType.NONE
            )
            return True
        if self.auth_required and Socks5AuthenticationType.PASSWORD in authmethods:
            clientsock.sendall(
                Socks5Server.SOCKSVERSION + Socks5AuthenticationType.PASSWORD
            )
        else:
            clientsock.sendall(Socks5Server.SOCKSVERSION + b"\xFF")
            logging.warning("client does not offer supported authentication types")
            return False

        if clientsock.recv(1) != Socks5Server.AUTH_PASSWORD_VERSION:
            msg = "Wrong Authentication Version"
            raise Socks5Error(msg)

        username_len: int = int.from_bytes(clientsock.recv(1), byteorder="big")
        username: str = clientsock.recv(username_len).decode("utf8")
        if len(username) != username_len:
            msg = "Invalid username length"
            raise Socks5Error(msg)

        password_len: int = int.from_bytes(clientsock.recv(1), byteorder="big")
        password: str = clientsock.recv(password_len).decode("utf8")
        if len(password) != password_len:
            msg = "Invalid password length"
            raise Socks5Error(msg)

        if self.check_credentials(username, password):
            clientsock.sendall(Socks5Server.AUTH_PASSWORD_VERSION + b"\x00")
            return True

        logging.warning("Authentication failed")
        clientsock.sendall(Socks5Server.AUTH_PASSWORD_VERSION + b"\x01")
        return False

    def _get_address(  # noqa: C901,PLR0915
        self, clientsock: Union[socket.socket, paramiko.Channel]
    ) -> Optional[Tuple[str, int]]:
        """Ermittelt das Ziel aus der Socks Anfrage"""
        # check socks version
        if clientsock.recv(1) != Socks5Server.SOCKSVERSION:
            msg = "Invalid Socks5 Version"
            raise Socks5Error(msg)
        # get socks command
        try:
            command = Socks5Command(clientsock.recv(1))
        except ValueError as exc:
            msg = "Invalid Socks5 command"
            raise Socks5Error(msg) from exc

        if clientsock.recv(1) != b"\x00":
            msg = "Reserved byte must be 0x00"
            raise Socks5Error(msg)

        try:
            address_type: Socks5AddressType = Socks5AddressType(clientsock.recv(1))
        except ValueError as exc:
            msg = "Invalid Socks5 address type"
            raise Socks5Error(msg) from exc

        dst_addr_b: bytes
        dst_addr: str
        dst_port_b: bytes
        dst_port: int

        if address_type is Socks5AddressType.IPv4:
            dst_addr_b, dst_port_b = clientsock.recv(4), clientsock.recv(2)
            if len(dst_addr_b) != 4 or len(dst_port_b) != 2:
                msg = "Invalid IPv4 Address"
                raise Socks5Error(msg)
            dst_addr = ".".join([str(i) for i in dst_addr_b])
        elif address_type is Socks5AddressType.DOMAIN:
            addr_len = int.from_bytes(clientsock.recv(1), byteorder="big")
            dst_addr_b, dst_port_b = clientsock.recv(addr_len), clientsock.recv(2)
            if len(dst_addr_b) != addr_len or len(dst_port_b) != 2:
                msg = "Invalid domain"
                raise Socks5Error(msg)
            dst_addr = "".join([chr(i) for i in dst_addr_b])
        elif address_type is Socks5AddressType.IPv6:
            dst_addr_b, dst_port_b = clientsock.recv(16), clientsock.recv(2)
            if len(dst_addr_b) != 16 or len(dst_port_b) != 2:
                msg = "Invalid IPv6 Address"
                raise Socks5Error(msg)
            tmp_addr = [
                chr(dst_addr_b[2 * i] * 256 + dst_addr_b[2 * i + 1])
                for i in range(int(len(dst_addr_b) / 2))
            ]
            dst_addr = ":".join(tmp_addr)
        else:
            msg = "Unhandled address type"
            raise Socks5Error(msg)

        dst_port = dst_port_b[0] * 256 + dst_port_b[1]

        address: Optional[Tuple[str, int]] = None
        reply = Socks5CommandReply.COMMAND_NOT_SUPPORTED
        if command is Socks5Command.CONNECT:
            address = (dst_addr, dst_port)
            reply = Socks5CommandReply.SUCCESS

        clientsock.sendall(
            Socks5Server.SOCKSVERSION
            + reply
            + b"\x00"
            + Socks5AddressType.IPv4
            + self.server_ip
            + self.server_port
        )
        return address

    def check_credentials(self, username: str, password: str) -> bool:
        """Prüft Benutzername und Passwort"""
        return username == self.username and password == self.password

    def get_address(
        self,
        clientsock: Union[socket.socket, paramiko.Channel],
        ignore_version: bool = False,
    ) -> Optional[Tuple[str, int]]:
        try:
            # check socks version
            if not ignore_version and clientsock.recv(1) != Socks5Server.SOCKSVERSION:
                msg = "Invalid Socks5 Version"
                raise Socks5Error(msg)
            if self._authenticate(clientsock):
                return self._get_address(clientsock)
        except Socks5Error as sockserror:
            logging.error("Socks5 Error: %s", str(sockserror))
        return None
