"""
Plugin for printing data as hexdump.

The SCPDebugForwarder class extends the SCPForwarder class,
and it implements the handle_client_data and handle_server_data methods to print
the data as hexdump. The print_hexdump method is a static method
that takes a bytes object and an optional int parameter
hexwidth and prints the data as a hexdump.
"""

from sshmitm.forwarders.scp import SCPForwarder
from sshmitm.utils import format_hex


class SCPDebugForwarder(SCPForwarder):
    """Prints raw SCP traffic to stdout as a hexdump for debugging.

    Intercepts all data exchanged between the SCP client and the remote server
    and prints it as a formatted hexdump to stdout. Both directions are shown
    separately — client-to-server and server-to-client.

    **Usage example**

    ::

        ssh-mitm server --scp-forwarder debug_traffic

    **Notes**

    * Output goes to stdout — redirect to a file if you need persistent capture.
    * The original data is forwarded unchanged; this plugin is read-only.
    """

    def handle_client_data(self, data: bytes) -> bytes:
        print("Client data:")
        print(format_hex(data))
        return super().handle_client_data(data)

    def handle_server_data(self, data: bytes) -> bytes:
        print("Server data:")
        print(format_hex(data))
        return super().handle_server_data(data)
