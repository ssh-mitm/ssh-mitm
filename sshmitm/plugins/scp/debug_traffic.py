"""
Plugin for printing traffic as hexdump.

The SCPDebugForwarder class extends the SCPForwarder class,
and it implements the handle_traffic method to print
the data as hexdump. The print_hexdump method is a static method
that takes a bytes object and an optional int parameter
hexwidth and prints the data as a hexdump.
"""

from sshmitm.forwarders.scp import SCPForwarder
from sshmitm.utils import format_hex


class SCPDebugForwarder(SCPForwarder):
    """print traffic as hexdump"""

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        print("Client data:" if isclient else "Server data:")
        print(format_hex(traffic))
        return traffic
