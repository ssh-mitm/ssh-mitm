import logging
import time
from typing import TYPE_CHECKING, Optional

import paramiko

from sshmitm.forwarders.scp import SCPBaseForwarder

if TYPE_CHECKING:
    import sshmitm


class NetconfBaseForwarder(SCPBaseForwarder):

    @property
    def client_channel(self) -> Optional[paramiko.Channel]:
        return self.session.netconf_channel

    def read_netconf_data(self, chan, responses=1):
        """
        Netconf messages mus tbe read until a special terminator is seen.
        A netconf message can be larger than the supported buffer length.
        """
        TERMINATOR = b"]]>]]>"

        response_buf = b""
        while responses:
            time.sleep(0.05)
            response = chan.recv(self.BUF_LEN)
            response_buf += response
            responses -= response.count(TERMINATOR)

        return response_buf


class NetconfForwarder(NetconfBaseForwarder):
    """forwards a netconf message from or to the remote server"""

    def forward(self) -> None:  # noqa: C901,PLR0915

        # pylint: disable=protected-access
        if self.session.ssh_pty_kwargs is not None:
            self.server_channel.get_pty(**self.session.ssh_pty_kwargs)

        if self.client_channel.eof_received:
            logging.debug("client channel eof received")
            self.server_channel.shutdown_write()
        if self.server_channel.eof_received:
            logging.debug("server channel eof received")
            self.client_channel.shutdown_write()

        # Invoke the netconf subsystem on the server.
        self.server_channel.invoke_subsystem("netconf")

        try:
            while self.session.running:
                if self.client_channel is None:
                    msg = "No Netconf Channel available!"
                    raise ValueError(msg)

                if self.client_channel.recv_ready():
                    buf = self.read_netconf_data(self.client_channel)
                    self.session.netconf_command = buf
                    self.sendall(self.server_channel, buf, self.server_channel.send)
                if self.server_channel.recv_ready():
                    buf = self.read_netconf_data(self.server_channel)
                    logging.info(
                        "received response: %s [isclient=%s] [command=%s]",
                        buf.decode("utf-8"),
                        False,
                        self.session.netconf_command,
                    )
                    self.sendall(self.client_channel, buf, self.client_channel.send)
                if self.client_channel.recv_stderr_ready():
                    buf = self.client_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handle_error(buf)
                    self.sendall(
                        self.server_channel, buf, self.server_channel.send_stderr
                    )
                if self.server_channel.recv_stderr_ready():
                    buf = self.server_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handle_error(buf)
                    self.sendall(
                        self.client_channel,
                        buf,
                        self.client_channel.send_stderr,
                    )

                if self.server_channel.exit_status_ready():
                    logging.debug("Exit from server ready")
                    status = self.server_channel.recv_exit_status()
                    self.server_exit_code_received = True
                    self.close_session_with_status(self.client_channel, status)
                    logging.info(
                        "remote netconf command '%s' exited with code: %s",
                        self.session.netconf_command.decode("utf-8"),
                        status,
                    )
                    time.sleep(0.1)
                    break
                if self.client_channel.exit_status_ready():
                    logging.debug("Exit from client ready")
                    status = self.client_channel.recv_exit_status()
                    self.client_exit_code_received = True
                    self.close_session(self.client_channel)
                    break

                if self._closed(self.client_channel):
                    logging.info("client channel closed")
                    self.server_channel.close()
                    self.close_session(self.client_channel)
                    break
                if self._closed(self.server_channel):
                    logging.info("server channel closed")
                    self.close_session(self.client_channel)
                    break
                if self.client_channel.eof_received:
                    logging.debug("client channel eof received")
                    self.server_channel.shutdown_write()
                if self.server_channel.eof_received:
                    logging.debug("server channel eof received")
                    self.client_channel.shutdown_write()

                time.sleep(0.1)
        except Exception:
            logging.exception("error processing netconf command")
            raise
