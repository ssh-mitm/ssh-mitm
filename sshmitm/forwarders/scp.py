import logging
import re
import time
from typing import TYPE_CHECKING, Callable, Optional

import paramiko
from paramiko.common import cMSG_CHANNEL_CLOSE, cMSG_CHANNEL_REQUEST
from paramiko.message import Message

from sshmitm.apps.mosh import handle_mosh
from sshmitm.forwarders.base import BaseForwarder

if TYPE_CHECKING:
    import sshmitm


class SCPBaseForwarder(BaseForwarder):
    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session)
        self.client_exit_code_received = False
        self.server_exit_code_received = False

    @property
    def client_channel(self) -> Optional[paramiko.Channel]:
        return self.session.scp_channel

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        del isclient  # unused arguments
        return traffic

    def handle_error(self, traffic: bytes) -> bytes:
        return traffic

    def rewrite_scp_command(self, command: str) -> str:
        logging.info("got remote command: %s", command)
        return command

    def forward(self) -> None:  # noqa: C901,PLR0915
        # pylint: disable=protected-access
        if self.session.ssh_pty_kwargs is not None:
            self.server_channel.get_pty(**self.session.ssh_pty_kwargs)

        self.session.scp_command = self.rewrite_scp_command(
            self.session.scp_command.decode("utf8")
        ).encode()
        self.server_channel.exec_command(self.session.scp_command)  # nosec

        # Wait for SCP remote to remote auth, command exec and copy to finish
        if self.session.scp_command.decode("utf8").startswith("scp"):
            if (
                self.session.scp_command.find(b" -t ") == -1
                and self.session.scp_command.find(b" -f ") == -1
            ):
                if self.client_channel is not None:
                    logging.debug(
                        "[chan %d] Initiating SCP remote to remote",
                        self.client_channel.get_id(),
                    )
                    if self.session.agent is None:
                        logging.warning(
                            "[chan %d] SCP remote to remote needs a forwarded agent",
                            self.client_channel.get_id(),
                        )
                while not self._closed(self.server_channel):
                    time.sleep(1)

        elif self.session.scp_command.decode("utf8").startswith("mosh-server"):
            while not self._closed(self.server_channel):
                time.sleep(1)

        try:
            while self.session.running:
                if self.client_channel is None:
                    msg = "No SCP Channel available!"
                    raise ValueError(msg)
                # redirect stdout <-> stdin und stderr <-> stderr
                if self.client_channel.recv_ready():
                    buf = self.client_channel.recv(self.BUF_LEN)
                    buf = self.handle_traffic(buf, isclient=True)
                    self.sendall(self.server_channel, buf, self.server_channel.send)
                if self.server_channel.recv_ready():
                    buf = self.server_channel.recv(self.BUF_LEN)
                    buf = self.handle_traffic(buf, isclient=False)
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
                        self.session.scp_command.decode("utf-8"),
                        status,
                    )
                    time.sleep(0.1)
                    break
                if self.client_channel.exit_status_ready():
                    logging.debug("Exit from client ready")
                    status = self.client_channel.recv_exit_status()
                    self.client_exit_code_received = True
                    # self.server_channel.send_exit_status(status)  # noqa: ERA001
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
            logging.exception("error processing scp command")
            raise

    def sendall(
        self, channel: paramiko.Channel, data: bytes, sendfunc: Callable[[bytes], int]
    ) -> int:
        if not data:
            return 0
        if channel.exit_status_ready():
            return 0
        
        sent = 0
        chunk_size = 32768  # Send in 32KB chunks to avoid overwhelming the channel
        total_len = len(data)
        
        while sent < total_len:
            # Check if channel is still active before each chunk
            if channel.closed or not channel.active:
                logging.warning("Channel closed during sendall, sent %d/%d bytes", sent, total_len)
                return sent
                
            # Calculate chunk size for this iteration
            remaining = total_len - sent
            current_chunk_size = min(chunk_size, remaining)
            chunk = data[sent:sent + current_chunk_size]
            
            try:
                newsent = sendfunc(chunk)
                if newsent == 0:
                    logging.warning("sendfunc returned 0, stopping transmission at %d/%d bytes", sent, total_len)
                    return sent
                sent += newsent
                
                # Small delay for large messages to prevent overwhelming the channel
                if total_len > 1024 * 1024:  # 1MB threshold
                    time.sleep(0.001)  # 1ms delay
                    
            except (EOFError, OSError) as e:
                logging.error("Error during sendall at %d/%d bytes: %s", sent, total_len, e)
                return sent
                
        return sent

    def close_session(self, channel: paramiko.Channel) -> None:
        self.close_session_with_status(channel=channel, status=None)

    def close_session_with_status(
        self, channel: paramiko.Channel, status: Optional[int]
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
        logging.debug("[chan %d] SCP closed", channel.get_id())


class SCPForwarder(SCPBaseForwarder):
    """forwards a file from or to the remote server"""

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session)

        self.await_response = False
        self.bytes_remaining = 0
        self.bytes_to_write = 0

        self.file_command: Optional[str] = None
        self.file_mode: Optional[str] = None
        self.file_size: int = 0
        self.file_name: str = ""

        self.got_c_command = False

    def handle_command(self, traffic: bytes) -> bytes:
        self.got_c_command = False
        command = traffic.decode("utf-8")

        match_c_command = re.match(r"([CD])([0-7]{4})\s([0-9]+)\s(.*)\n", command)
        if not match_c_command:
            match_e_command = re.match(r"(E)\n", command)
            if match_e_command:
                logging.debug("got command %s", command.strip())
            match_t_command = re.match(
                r"(T)([0-9]+)\s([0-9]+)\s([0-9]+)\s([0-9]+)\n", command
            )
            if match_t_command:
                logging.debug("got command %s", command.strip())
            return traffic

        # setze Name, Dateigröße und das zu sendende Kommando
        logging.debug("got command %s", command.strip())
        self.got_c_command = True

        self.file_command = match_c_command[1]
        self.file_mode = match_c_command[2]
        self.bytes_remaining = self.file_size = int(match_c_command[3])
        self.file_name = match_c_command[4]

        # next traffic package is a respone package
        self.await_response = True
        return traffic

    def process_data(self, traffic: bytes) -> bytes:
        return traffic

    def process_response(self, traffic: bytes) -> bytes:
        return traffic

    def handle_scp(self, traffic: bytes) -> bytes:
        # handle scp responses (OK 0x00, WARN 0x01, ERR 0x02)
        if self.await_response:
            self.await_response = False
            return self.process_response(traffic)

        if self.bytes_remaining == 0 and not self.got_c_command:
            return self.handle_command(traffic)

        self.got_c_command = False
        return self.process_data(traffic)

    def process_command_data(
        self, command: bytes, traffic: bytes, isclient: bool
    ) -> bytes:
        del command
        del isclient
        return traffic

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        if self.session.scp_command.startswith(b"scp"):
            return self.handle_scp(traffic)
        if self.session.scp_command.startswith(b"mosh-server"):
            return handle_mosh(self.session, traffic, isclient)
        return self.process_command_data(self.session.scp_command, traffic, isclient)
