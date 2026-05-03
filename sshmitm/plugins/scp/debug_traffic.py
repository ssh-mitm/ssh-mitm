"""
Plugin for printing traffic as hexdump.

The SCPDebugForwarder class extends the SCPForwarder class,
and it implements the handle_client_data and handle_server_data methods to print
the data as hexdump. The print_hexdump method is a static method
that takes a bytes object and an optional int parameter
hexwidth and prints the data as a hexdump.
"""

from sshmitm.core.scp import SCPForwarder
from sshmitm.utils import format_hex


class SCPDebugForwarder(SCPForwarder):
    """print traffic as hexdump"""

    def handle_client_data(self, traffic: bytes) -> bytes:
        print("Client data:")
        print(format_hex(traffic))
        return super().handle_client_data(traffic)

    def handle_server_data(self, traffic: bytes) -> bytes:
        print("Server data:")
        print(format_hex(traffic))
        return super().handle_server_data(traffic)
