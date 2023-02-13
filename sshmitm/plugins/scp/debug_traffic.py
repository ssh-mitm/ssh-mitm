"""
Plugin for printing traffic as hexdump.

The SCPDebugForwarder class extends the SCPForwarder class,
and it implements the handle_traffic method to print
the data as hexdump. The print_hexdump method is a static method
that takes a bytes object and an optional int parameter
hexwidth and prints the data as a hexdump.
"""

import binascii

from sshmitm.forwarders.scp import SCPForwarder


class SCPDebugForwarder(SCPForwarder):
    """print traffic as hexdump
    """

    @staticmethod
    def print_hexdump(traffic: bytes, hexwidth: int = 16) -> None:
        """prints the provided data as hexdump"""
        result = []

        for i in range(0, len(traffic), hexwidth):
            data_part = traffic[i:i + hexwidth]
            hexa = list(map(''.join, zip(*[iter(binascii.hexlify(data_part).decode('utf-8'))] * 2)))
            while hexwidth - len(hexa) > 0:
                hexa.append(' ' * 2)
            text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in data_part])
            addr = '%04X:    %s    %s' % (i, " ".join(hexa), text)  # pylint: disable=consider-using-f-string
            result.append(addr)

        print('\n'.join(result))

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        print("Client data:" if isclient else "Server data:")
        self.print_hexdump(traffic)
        return traffic
