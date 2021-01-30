import time
import binascii

from typing import (
    Optional
)

from enhancements.modules import Module


class TcpProxyHandler(Module):

    def process(self, isclient: bool, data: Optional[bytes]) -> Optional[bytes]:
        if not data:
            return None
        try:
            execute_func = self.execute_client if isclient else self.execute_server
            return execute_func(data)
        except NotImplementedError:
            try:
                return self.execute(isclient, data)
            except NotImplementedError:
                return data

    def execute(self, isclient: bool, data: bytes) -> Optional[bytes]:
        raise NotImplementedError()

    def execute_client(self, data: bytes) -> Optional[bytes]:
        raise NotImplementedError()

    def execute_server(self, data: bytes) -> Optional[bytes]:
        raise NotImplementedError()

    def on_close(self) -> None:
        pass


class TcpProxySaveHandler(TcpProxyHandler):

    @classmethod
    def parser_arguments(cls) -> None:
        cls.PARSER.add_argument(
            '--file',
            dest='filepath',
            help='filepath to store data'
        )

    def execute(self, isclient: bool, data: bytes) -> Optional[bytes]:
        with open(self.args.filepath, 'ab') as the_file:
            the_file.write(data)
        return data


class TcpProxyHexDump(TcpProxyHandler):

    @classmethod
    def parser_arguments(cls) -> None:
        cls.PARSER.add_argument(
            '--hexwidth',
            dest='hexwidth',
            type=int,
            default=16,
            help='width of the hexdump in chars'
        )

    def execute(self, isclient: bool, data: bytes) -> Optional[bytes]:
        # this is a pretty hex dumping function directly taken from
        # http://code.activestate.com/recipes/142812-hex-dumper/
        print("{}:".format("Client" if isclient else "Server"))
        result = []

        for i in range(0, len(data), self.args.hexwidth):
            s = data[i:i + self.args.hexwidth]
            hexa = list(map(''.join, zip(*[iter(binascii.hexlify(s).decode('utf-8'))] * 2)))
            while self.args.hexwidth - len(hexa) > 0:
                hexa.append(' ' * 2)
            text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in s])
            addr = '%04X:    %s    %s' % (i, " ".join(hexa), text)
            result.append(addr)

        print('\n'.join(result))
        return data


class TcpProxyDropHandler(TcpProxyHandler):

    @classmethod
    def parser_arguments(cls) -> None:
        cls.PARSER.add_argument(
            '--dropclient',
            dest='dropclient',
            default=False,
            action='store_true',
            help='drop client data'
        )
        cls.PARSER.add_argument(
            '--dropserver',
            dest='dropserver',
            default=False,
            action='store_true',
            help='drop server data'
        )

    def execute_client(self, data: bytes) -> Optional[bytes]:
        return None if self.args.dropclient else data

    def execute_server(self, data: bytes) -> Optional[bytes]:
        return None if self.args.dropserver else data


class TcpProxyWaitHandler(TcpProxyHandler):

    @classmethod
    def parser_arguments(cls) -> None:
        cls.PARSER.add_argument(
            '--wait',
            dest='waitseconds',
            type=int,
            default=10,
            help='seconds to wait'
        )

    def execute(self, isclient: bool, data: bytes) -> Optional[bytes]:
        time.sleep(self.args.waitseconds)
        return data
