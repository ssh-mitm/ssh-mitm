import binascii
from ssh_proxy_server.forwarders.scp import SCPForwarder


class SCPDebugForwarder(SCPForwarder):
    """print traffic as hexdump
    """

    @staticmethod
    def print_hexdump(traffic, hexwidth=16):
        result = []

        for i in range(0, len(traffic), hexwidth):
            s = traffic[i:i + hexwidth]
            hexa = list(map(''.join, zip(*[iter(binascii.hexlify(s).decode('utf-8'))] * 2)))
            while hexwidth - len(hexa) > 0:
                hexa.append(' ' * 2)
            text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in s])
            addr = '%04X:    %s    %s' % (i, " ".join(hexa), text)
            result.append(addr)

        print('\n'.join(result))

    def handle_traffic(self, traffic, isclient):
        print("Client data:" if isclient else "Server data:")
        self.print_hexdump(traffic)
        return traffic