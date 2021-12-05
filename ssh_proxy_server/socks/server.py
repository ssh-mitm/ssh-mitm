# type: ignore
from enum import Enum
import logging

class Socks5Error(Exception):
    pass


class Socks5Types(Enum):
    """Basisklasse für Socks5 Daten"""

    def __str__(self):
        return self.value

    def __add__(self, other):
        return self.value + other

    def __radd__(self, other):
        return other + self.value


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
    IPv4 = b"\x01"
    DOMAIN = b"\x03"
    IPv6 = b"\x04"


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

    def __init__(self, listenaddress, username=None, password=None):
        self.listenaddress = listenaddress
        self.username = username
        self.password = password
        self.auth_required = self.username and self.password

    @property
    def server_ip(self):
        """Liefert die IP Adresse des Socks Proxy zurück"""
        return b"".join([bytes([int(i)]) for i in self.listenaddress[0].split(".")])

    @property
    def server_port(self):
        """Liefert den Port den Socks Proxy zurück"""
        server_port = self.listenaddress[1]
        return bytes([int(server_port / 256)]) + bytes([int(server_port % 256)])


    def _get_auth_methods(self, clientsock):
        """Ermittelt die angebotenen Authentifizierungsmechanismen"""
        if clientsock.recv(1) != Socks5Server.SOCKSVERSION:
            raise Socks5Error("Invalid Socks5 Version")
        methods_count = int.from_bytes(clientsock.recv(1), byteorder='big')
        try:
            methods = [Socks5AuthenticationType(bytes([m])) for m in clientsock.recv(methods_count)]
        except ValueError:
            raise Socks5Error("Invalid methods")
        if len(methods) != methods_count:
            raise Socks5Error("Invalid number of methods")
        return methods

    def _authenticate(self, clientsock):
        """Authentifiziert den Benutzer"""
        authmethods = self._get_auth_methods(clientsock)

        if not self.auth_required and Socks5AuthenticationType.NONE in authmethods:
            clientsock.sendall(Socks5Server.SOCKSVERSION + Socks5AuthenticationType.NONE)
            return True
        elif self.auth_required and Socks5AuthenticationType.PASSWORD in authmethods:
            clientsock.sendall(Socks5Server.SOCKSVERSION + Socks5AuthenticationType.PASSWORD)
        else:
            clientsock.sendall(Socks5Server.SOCKSVERSION + b"\xFF")
            logging.warning("client does not offer supported authentication types")
            return False

        if Socks5Server.AUTH_PASSWORD_VERSION != clientsock.recv(1):
            raise Socks5Error('Wrong Authentication Version')

        username_len = int.from_bytes(clientsock.recv(1), byteorder='big')
        username = clientsock.recv(username_len).decode("utf8")
        if len(username) != username_len:
            raise Socks5Error("Invalid username length")

        password_len = int.from_bytes(clientsock.recv(1), byteorder='big')
        password = clientsock.recv(password_len).decode("utf8")
        if len(password) != password_len:
            raise Socks5Error("Invalid password length")

        if self.check_credentials(username, password):
            clientsock.sendall(Socks5Server.AUTH_PASSWORD_VERSION + b"\x00")
            return True

        logging.warning("Authentication failed")
        clientsock.sendall(Socks5Server.AUTH_PASSWORD_VERSION + b"\x01")
        return False

    def _get_address(self, clientsock):
        """Ermittelt das Ziel aus der Socks Anfrage"""
        # check socks version
        if clientsock.recv(1) != Socks5Server.SOCKSVERSION:
            raise Socks5Error("Invalid Socks5 Version")
        # get socks command
        try:
            command = Socks5Command(clientsock.recv(1))
        except ValueError:
            raise Socks5Error("Invalid Socks5 command")

        if clientsock.recv(1) != b"\x00":
            raise Socks5Error("Reserved byte must be 0x00")

        try:
            address_type = Socks5AddressType(clientsock.recv(1))
        except ValueError:
            raise Socks5Error("Invalid Socks5 address type")

        if address_type is Socks5AddressType.IPv4:
            dst_addr, dst_port = clientsock.recv(4), clientsock.recv(2)
            if len(dst_addr) != 4 and dst_port != 2:
                raise Socks5Error("Invalid IPv4 Address")
            dst_addr = ".".join([str(i) for i in dst_addr])
        elif address_type is Socks5AddressType.DOMAIN:
            addr_len = int.from_bytes(clientsock.recv(1), byteorder='big')
            dst_addr, dst_port = clientsock.recv(addr_len), clientsock.recv(2)
            if len(dst_addr) != addr_len and dst_port != 2:
                raise Socks5Error("Invalid domain")
            dst_addr = "".join([chr(i) for i in dst_addr])
        elif address_type is Socks5AddressType.IPv6:
            dst_addr, dst_port = clientsock.recv(16), clientsock.recv(2)
            if len(dst_addr) != 16 and dst_port != 2:
                raise Socks5Error("Invalid IPv6 Address")
            tmp_addr = []
            for i in range(len(dst_addr) / 2):
                tmp_addr.append(chr(dst_addr[2 * i] * 256 + dst_addr[2 * i + 1]))
            dst_addr = ":".join(tmp_addr)
        else:
            raise Socks5Error("Unhandled address type")

        dst_port = dst_port[0] * 256 + dst_port[1]

        address = None
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

    def check_credentials(self, username, password):
        """Prüft Benutzername und Passwort"""
        return username == self.username and password == self.password

    def get_address(self, clientsock):
        try:
            if self._authenticate(clientsock):
                return self._get_address(clientsock)
        except Socks5Error as sockserror:
            logging.error("Socks5 Error: %s", str(sockserror))
        return None

if __name__ == '__main__':

    import socket
    import sys

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 10000)
    sock.bind(server_address)
    # Listen for incoming connections
    sock.listen(1)

    while True:
        # Wait for a connection
        connection, client_address = sock.accept()
        try:
            print('connection from %s', client_address)

            s = Socks5Server(('0.0.0.0', 10000))
            print(s.get_address(connection))

        finally:
            # Clean up the connection
            connection.close()
