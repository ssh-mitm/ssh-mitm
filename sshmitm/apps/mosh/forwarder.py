import time
from typing import TYPE_CHECKING

import paramiko

from sshmitm.apps.mosh.proxy import handle_mosh
from sshmitm.forwarders.scp import SCPBaseForwarder

if TYPE_CHECKING:
    import sshmitm


class MoshForwarder(SCPBaseForwarder):
    """Forwarder for MOSH (Mobile Shell) sessions.

    Executes the mosh-server command, waits for the MOSH CONNECT handshake
    to complete (server channel closes after sending it), then reads the
    buffered response and rewrites the port to point at the UDP proxy.
    """

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return self.session.scp_channel

    @property
    def _forwarded_command(self) -> bytes:
        return self.session.scp_command

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        return handle_mosh(self.session, traffic, isclient)

    def forward(self) -> None:
        self.server_channel.exec_command(self.session.scp_command)  # nosec
        while not self._closed(self.server_channel):
            time.sleep(1)
        self._run_traffic_loop()


SCPBaseForwarder.register_exec_handler(
    b"mosh-server",
    MoshForwarder,
    disable_pty=True,
    disable_ssh=True,
)
