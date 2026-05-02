import logging
import time
from abc import abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING

import paramiko
from paramiko.common import cMSG_CHANNEL_CLOSE, cMSG_CHANNEL_REQUEST
from paramiko.message import Message

from sshmitm.forwarders.base import BaseForwarder

if TYPE_CHECKING:
    import sshmitm


class ExecForwarder(BaseForwarder):
    """Base class for all exec-command-based forwarders (SCP, NETCONF, Mosh, …).

    Provides the bidirectional traffic loop, reliable sendall helper, and
    channel-teardown logic that all exec-style protocols share.  Subclasses
    must implement :attr:`client_channel`, :attr:`_forwarded_command`, and
    :meth:`forward`.
    """

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session)
        self.client_exit_code_received = False
        self.server_exit_code_received = False

    @property
    @abstractmethod
    def _forwarded_command(self) -> bytes:
        """The command being forwarded, used in log messages."""

    def handle_client_data(self, data: bytes) -> bytes:
        return data

    def handle_server_data(self, data: bytes) -> bytes:
        return data

    def handle_error(self, data: bytes) -> bytes:
        return data

    def _run_traffic_loop(self) -> None:  # noqa: C901, PLR0915
        try:
            while self.session.running:
                if self.client_channel is None:
                    msg = "No channel available!"
                    raise ValueError(msg)
                if self.client_channel.recv_ready():
                    buf = self.client_channel.recv(self.BUF_LEN)
                    buf = self.handle_client_data(buf)
                    self.sendall(self.server_channel, buf, self.server_channel.send)
                if self.server_channel.recv_ready():
                    buf = self.server_channel.recv(self.BUF_LEN)
                    buf = self.handle_server_data(buf)
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
                        "remote command '%s' exited with code: %s",
                        self._forwarded_command.decode("utf-8"),
                        status,
                    )
                    time.sleep(0.1)
                    break
                if self.client_channel.exit_status_ready():
                    logging.debug("Exit from client ready")
                    self.client_exit_code_received = True
                    self.client_channel.recv_exit_status()
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
            logging.exception("error processing exec command")
            raise

    def sendall(
        self, channel: paramiko.Channel, data: bytes, sendfunc: Callable[[bytes], int]
    ) -> int:
        if not data:
            return 0
        if channel.exit_status_ready():
            return 0
        sent = 0
        newsent = 0
        while sent != len(data):
            newsent = sendfunc(data[sent:])
            if newsent == 0:
                return 0
            sent += newsent
        return sent

    def close_session(self, channel: paramiko.Channel) -> None:
        self.close_session_with_status(channel=channel, status=None)

    def close_session_with_status(
        self, channel: paramiko.Channel, status: int | None
    ) -> None:
        # pylint: disable=protected-access
        if channel.closed:
            return

        if self.server_exit_code_received:
            if status is not None and self.client_channel is not None:
                self.client_channel.send_exit_status(status)
                logging.debug("sent exit status to client: %s", status)

            message = Message()
            message.add_byte(cMSG_CHANNEL_REQUEST)
            message.add_int(channel.remote_chanid)
            message.add_string("eow@openssh.com")
            message.add_boolean(False)
            channel.transport._send_user_message(message)  # type: ignore[union-attr]

        message = Message()
        message.add_byte(cMSG_CHANNEL_CLOSE)
        message.add_int(channel.remote_chanid)
        channel.transport._send_user_message(message)  # type: ignore[union-attr]

        channel._unlink()  # type: ignore[attr-defined]

        super().close_session(channel)
        logging.debug("[chan %d] closed", channel.get_id())
