import time

import paramiko

from sshmitm.apps.mosh.proxy import handle_mosh
from sshmitm.forwarders.exec import ExecForwarder
from sshmitm.forwarders.scp import SCPBaseForwarder


class MoshForwarder(ExecForwarder):
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

    def handle_client_data(self, traffic: bytes) -> bytes:
        return handle_mosh(self.session, traffic, True)

    def handle_server_data(self, traffic: bytes) -> bytes:
        return handle_mosh(self.session, traffic, False)

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
