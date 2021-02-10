import logging
import sys
from enum import Enum
import socket

from enhancements.modules import BaseModule
from tcp_proxy_server.exceptions import Socks5Error


class TcpProxyForwardAddress(object):

    def __init__(self, address=None, socket=None, data=None):
        self.address = address
        self.data = data
        self.socket = socket


class TcpProxyForwarder(BaseModule):

    def __init__(self, server):
        super().__init__()
        self.server = server
        self.remoteaddress = (None, None)

    @classmethod
    def start(cls, proxyargs):
        return False

    def get_address(self, clientsock, clientaddr):
        raise NotImplementedError


class SimpleForwarder(TcpProxyForwarder):
    """forward data to a single remote server"""

    def __init__(self, server):
        super().__init__(server)
        self.targetip = self.args.target_ip
        self.targetport = self.args.target_port

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '-ti',
            '--targetip',
            dest='target_ip',
            required=True,
            help='remote target IP'
        )
        cls.parser().add_argument(
            '-tp',
            '--targetport',
            dest='target_port',
            type=int,
            required=True,
            help='remote target port'
        )

    def get_address(self, clientsock, clientaddr):
        return TcpProxyForwardAddress(address=(self.targetip, self.targetport))


class SimpleOptionalForwarder(SimpleForwarder):
    """forwarder wich does not require remote address to be set with command line args
    This forwarder should not be used as command line argument!
    """

    def __init__(self, server):
        super().__init__(server)
        self.targetip = self.args.target_ip
        self.targetport = self.args.target_port

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '-ti',
            '--targetip',
            dest='target_ip',
            default=None,
            help='remote target IP'
        )
        cls.parser().add_argument(
            '-tp',
            '--targetport',
            dest='target_port',
            type=int,
            default=None,
            help='remote target port'
        )

    def get_address(self, clientsock, clientaddr):
        address = (self.targetip or self.remoteaddress[0], self.targetport or self.remoteaddress[1])
        return TcpProxyForwardAddress(address=address)


class TProxyForwarder(TcpProxyForwarder):
    """support for TProxy from Linux Kernel"""

    def __init__(self, server):
        super().__init__(server)
        server.server.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
        self.targetip = self.args.target_ip
        self.targetport = self.args.target_port

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '-ti',
            '--targetip',
            dest='target_ip',
            default=None,
            help='remote target IP'
        )
        cls.parser().add_argument(
            '-tp',
            '--targetport',
            dest='target_port',
            type=int,
            default=None,
            help='remote target port'
        )

    def get_address(self, clientsock, clientaddr):
        host = self.targetip or clientsock.getsockname()[0]
        port = self.targetport or clientsock.getsockname()[1]
        if self.targetip or self.targetport:
            logging.debug('%s: try to connect to %s instead of %s', clientaddr, (host, port), clientsock.getsockname())
        else:
            logging.debug("%s: try to connect to %s", clientaddr, (host, port))
        return TcpProxyForwardAddress(address=(host, port))


class Socks5Forwarder(TcpProxyForwarder):
    """forwards the data to a socks5 server"""

    class Socks5Types(Enum):

        def __str__(self):
            return self.value

        def __add__(self, other):
            return self.value + other

        def __radd__(self, other):
            return other + self.value

    class AuthenticationType(Socks5Types):
        NONE = b"\x00"
        PASSWORD = b"\x02"

    class Command(Socks5Types):
        CONNECT = b"\x01"
        BIND = b"\x02"
        UDP = b"\x03"

    class AddressType(Socks5Types):
        IPv4 = b"\x01"
        DOMAIN = b"\x03"
        IPv6 = b"\x04"

    class CommandReply(Socks5Types):
        SUCCESS = b"\x00"
        GENERAL_FAILURE = b"\x01"
        CONNECTION_NOT_ALLOWED = b"\x02"
        NETWORK_UNREACHABLE = b"\x03"
        HOST_UNREACHABLE = b"\x04"
        CONNECTION_REFUSED = b"\x05"
        TTL_EXPIRED = b"\x06"
        COMMAND_NOT_SUPPORTED = b"\x07"
        ADDR_TYPE_NOT_SUPPORTED = b"\x00"

    SOCKSVERSION = b"\x05"
    AUTH_PASSWORD_VERSION = b"\x01"

    def __init__(self, server):
        super().__init__(server)
        self.username = self.args.username
        self.password = self.args.password
        self.auth_required = self.username and self.password

    @property
    def server_ip(self):
        return b"".join([bytes([int(i)]) for i in self.server.listenaddress[0].split(".")])

    @property
    def server_port(self):
        server_port = self.server.listenaddress[1]
        return bytes([int(server_port / 256)]) + bytes([int(server_port % 256)])

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--username',
            dest='username',
            default=None,
            required='--password' in sys.argv,
            help='username to authenticate'
        )
        cls.parser().add_argument(
            '--password',
            dest='password',
            default=None,
            required='--username' in sys.argv,
            help='password to authenticate'
        )

    def _get_auth_methods(self, clientsock):
        if clientsock.recv(1) != Socks5Forwarder.SOCKSVERSION:
            raise Socks5Error("Invalid Socks5 Version")
        methods_count = int.from_bytes(clientsock.recv(1), byteorder='big')
        try:
            methods = [Socks5Forwarder.AuthenticationType(bytes([m])) for m in clientsock.recv(methods_count)]
        except ValueError:
            raise Socks5Error("Invalid methods")
        if len(methods) != methods_count:
            raise Socks5Error("Invalid number of methods")
        return methods

    def _authenticate(self, clientsock):
        authmethods = self._get_auth_methods(clientsock)

        if not self.auth_required and Socks5Forwarder.AuthenticationType.NONE in authmethods:
            clientsock.sendall(Socks5Forwarder.SOCKSVERSION + Socks5Forwarder.AuthenticationType.NONE)
            return True

        if self.auth_required and Socks5Forwarder.AuthenticationType.PASSWORD in authmethods:
            clientsock.sendall(Socks5Forwarder.SOCKSVERSION + Socks5Forwarder.AuthenticationType.PASSWORD)
        else:
            clientsock.sendall(Socks5Forwarder.SOCKSVERSION + b"\xFF")
            logging.warning("client does not offer supported authentication types")
            return False

        if Socks5Forwarder.AUTH_PASSWORD_VERSION != clientsock.recv(1):
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
            clientsock.sendall(Socks5Forwarder.AUTH_PASSWORD_VERSION + b"\x00")
            return True

        logging.warning("Authentication failed")
        clientsock.sendall(Socks5Forwarder.AUTH_PASSWORD_VERSION + b"\x01")
        return False

    def _get_address(self, clientsock):
        # check socks version
        if clientsock.recv(1) != Socks5Forwarder.SOCKSVERSION:
            raise Socks5Error("Invalid Socks5 Version")
        # get socks command
        try:
            command = Socks5Forwarder.Command(clientsock.recv(1))
        except ValueError:
            raise Socks5Error("Invalid Socks5 command")

        if clientsock.recv(1) != b"\x00":
            raise Socks5Error("Reserved byte must be 0x00")

        try:
            address_type = Socks5Forwarder.AddressType(clientsock.recv(1))
        except ValueError:
            raise Socks5Error("Invalid Socks5 address type")

        if address_type is Socks5Forwarder.AddressType.IPv4:
            dst_addr, dst_port = clientsock.recv(4), clientsock.recv(2)
            if len(dst_addr) != 4 and dst_port != 2:
                raise Socks5Error("Invalid IPv4 Address")
            dst_addr = ".".join([str(i) for i in dst_addr])
        elif address_type is Socks5Forwarder.AddressType.DOMAIN:
            addr_len = int.from_bytes(clientsock.recv(1), byteorder='big')
            dst_addr, dst_port = clientsock.recv(addr_len), clientsock.recv(2)
            if len(dst_addr) != addr_len and dst_port != 2:
                raise Socks5Error("Invalid domain")
            dst_addr = "".join([chr(i) for i in dst_addr])
        elif address_type is Socks5Forwarder.AddressType.IPv6:
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
        reply = Socks5Forwarder.CommandReply.COMMAND_NOT_SUPPORTED
        if command is Socks5Forwarder.Command.CONNECT:
            address = (dst_addr, dst_port)
            reply = Socks5Forwarder.CommandReply.SUCCESS

        clientsock.sendall(
            Socks5Forwarder.SOCKSVERSION +
            reply +
            b"\x00" +
            Socks5Forwarder.AddressType.IPv4 +
            self.server_ip +
            self.server_port
        )

        return address

    def check_credentials(self, username, password):
        return username == self.username and password == self.password

    def get_address(self, clientsock, clientaddr):
        try:
            if self._authenticate(clientsock):
                return TcpProxyForwardAddress(address=self._get_address(clientsock))
        except Socks5Error as sockserror:
            logging.error("Socks5 Error: %s", str(sockserror))
        return TcpProxyForwardAddress()


class EchoForwarder(TcpProxyForwarder):
    """send data back to the client (echo server)"""

    def get_address(self, clientsock, clientaddr):
        return TcpProxyForwardAddress(socket=clientsock)
