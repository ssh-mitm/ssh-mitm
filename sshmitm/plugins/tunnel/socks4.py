import logging
import socket
from enum import Enum
from typing import Optional, Tuple, Union, cast

import paramiko


class Socks4Error(Exception):
    pass


class Socks4Types(Enum):
    """Basisklasse für Socks4 Daten"""

    def __str__(self) -> str:
        return str(self.value)

    def __add__(self, other: bytes) -> bytes:
        return cast(bytes, self.value) + other

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


class Socks4Server:
    """Socks4 kompatibler Forwarder"""

    SOCKSVERSION = b"\x04"

    def __init__(self, listenaddress: Tuple[str, int]) -> None:
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

    def _get_address(
        self, clientsock: Union[socket.socket, paramiko.Channel]
    ) -> Optional[Tuple[str, int]]:
        """Ermittelt das Ziel aus der Socks Anfrage"""
        # get socks command
        try:
            command = Socks4Command(clientsock.recv(1))
        except ValueError as exc:
            msg = "Invalid Socks4 command"
            raise Socks4Error(msg) from exc

        dst_addr_b: bytes
        dst_addr: str
        dst_port_b: bytes
        dst_port: int

        dst_port_b, dst_addr_b = clientsock.recv(2), clientsock.recv(4)
        if len(dst_addr_b) != 4 or len(dst_port_b) != 2:
            msg = "Invalid IPv4 Address"
            raise Socks4Error(msg)
        dst_addr = ".".join([str(i) for i in dst_addr_b])
        dst_port = dst_port_b[0] * 256 + dst_port_b[1]

        continue_recv = True
        userid = b""
        while continue_recv:
            nextchr = clientsock.recv(1)
            if nextchr == b"\x00":
                break
            userid += nextchr

        address: Optional[Tuple[str, int]] = None
        reply = Socks4CommandReply.FAILED
        if command is Socks4Command.CONNECT:
            address = (dst_addr, dst_port)
            reply = Socks4CommandReply.SUCCESS

        clientsock.sendall(b"\x00" + reply + self.server_port + self.server_ip)
        return address

    def get_address(
        self,
        clientsock: Union[socket.socket, paramiko.Channel],
        ignore_version: bool = False,
    ) -> Optional[Tuple[str, int]]:
        try:
            # check socks version
            if not ignore_version and clientsock.recv(1) != Socks4Server.SOCKSVERSION:
                msg = "Invalid Socks4 Version"
                raise Socks4Error(msg)
            return self._get_address(clientsock)
        except Socks4Error as sockserror:
            logging.error("Socks4 Error: %s", str(sockserror))
        return None
