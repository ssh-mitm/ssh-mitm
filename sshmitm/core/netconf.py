import time

import paramiko

from sshmitm.forwarders.exec import ExecForwarder


class NetconfBaseForwarder(ExecForwarder):
    """Base class for NETCONF SSH-subsystem forwarders."""

    # RFC 4742 end-of-message delimiter; RFC 6242 chunked framing is not supported.
    __netconf_terminator = b"]]>]]>"

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return self.session.netconf_channel

    @property
    def _forwarded_command(self) -> bytes:
        return self.session.netconf.command

    def read_netconf_data(self, chan: paramiko.Channel, responses: int = 1) -> bytes:
        # WARNING: busy-loop with 50 ms sleep; no timeout; hangs on chunked framing.
        response_buf = b""
        while responses:
            time.sleep(0.05)
            response = chan.recv(self.BUF_LEN)
            response_buf += response
            responses -= response.count(self.__netconf_terminator)
        return response_buf

    def forward(self) -> None:
        """Forwards data between the client and the server"""
        msg = "Method forward is not used in Netconf Forwarder"
        raise NotImplementedError(msg)
