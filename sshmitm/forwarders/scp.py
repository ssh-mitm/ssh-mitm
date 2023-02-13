import logging
import time
import re
from typing import (
    Callable,
    Optional
)

import paramiko
from paramiko.common import cMSG_CHANNEL_REQUEST, cMSG_CHANNEL_CLOSE, cMSG_CHANNEL_EOF
from paramiko.message import Message

import sshmitm
from sshmitm.forwarders.base import BaseForwarder
from sshmitm.apps.mosh import handle_mosh


class SCPBaseForwarder(BaseForwarder):

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        del isclient  # unused arguments
        return traffic

    def handle_error(self, traffic: bytes) -> bytes:
        return traffic

    def rewrite_scp_command(self, command: str) -> str:
        logging.info("got remote command: %s", command)
        return command

    def forward(self) -> None:
        # pylint: disable=protected-access
        if self.session.ssh_pty_kwargs is not None:
            self.server_channel.get_pty(**self.session.ssh_pty_kwargs)

        self.session.scp_command = self.rewrite_scp_command(self.session.scp_command.decode('utf8')).encode()
        self.server_channel.exec_command(self.session.scp_command)  # nosec

        # Wait for SCP remote to remote auth, command exec and copy to finish
        if self.session.scp_command.decode('utf8').startswith('scp'):
            if not self.session.scp_command.find(b' -t ') != -1 and not self.session.scp_command.find(b' -f ') != -1:
                if self.session.scp_channel is not None:
                    logging.debug("[chan %d] Initiating SCP remote to remote", self.session.scp_channel.get_id())
                    if self.session.agent is None:
                        logging.warning(
                            "[chan %d] SCP remote to remote needs a forwarded agent", self.session.scp_channel.get_id()
                        )
                while not self._closed(self.server_channel):
                    time.sleep(1)

        elif self.session.scp_command.decode('utf8').startswith('mosh-server'):
            while not self._closed(self.server_channel):
                time.sleep(1)

        try:
            while self.session.running:
                if self.session.scp_channel is None:
                    raise ValueError("No SCP Channel available!")
                # redirect stdout <-> stdin und stderr <-> stderr
                if self.session.scp_channel.recv_ready():
                    buf = self.session.scp_channel.recv(self.BUF_LEN)
                    buf = self.handle_traffic(buf, isclient=True)
                    self.sendall(self.server_channel, buf, self.server_channel.send)
                if self.server_channel.recv_ready():
                    buf = self.server_channel.recv(self.BUF_LEN)
                    buf = self.handle_traffic(buf, isclient=False)
                    self.sendall(self.session.scp_channel, buf, self.session.scp_channel.send)
                if self.session.scp_channel.recv_stderr_ready():
                    buf = self.session.scp_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handle_error(buf)
                    self.sendall(self.server_channel, buf, self.server_channel.send_stderr)
                if self.server_channel.recv_stderr_ready():
                    buf = self.server_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handle_error(buf)
                    self.sendall(self.session.scp_channel, buf, self.session.scp_channel.send_stderr)

                if self.server_channel.exit_status_ready():
                    status = self.server_channel.recv_exit_status()
                    self.close_session_with_status(self.session.scp_channel, status)
                    logging.info(
                        "remote command '%s' exited with code: %s",
                        self.session.scp_command.decode('utf-8'), status
                    )
                    time.sleep(0.1)
                    break
                if self.session.scp_channel.exit_status_ready():
                    status = self.session.scp_channel.recv_exit_status()
                    # self.server_channel.send_exit_status(status)
                    self.close_session(self.session.scp_channel)
                    break

                if self._closed(self.session.scp_channel):
                    logging.info("client channel closed")
                    self.server_channel.close()
                    self.close_session(self.session.scp_channel)
                    break
                if self._closed(self.server_channel):
                    logging.info("server channel closed")
                    self.close_session(self.session.scp_channel)
                    break
                if self.session.scp_channel.eof_received:
                    message = Message()
                    message.add_byte(cMSG_CHANNEL_EOF)
                    message.add_int(self.session.scp_channel.remote_chanid)
                    if self.session.scp_channel.transport is not None:
                        self.session.scp_channel.transport._send_user_message(message)  # type: ignore
                    self.session.scp_channel.send_exit_status(0)
                    self.close_session(self.session.scp_channel)
                    break

                time.sleep(0.1)
        except Exception:
            logging.exception('error processing scp command')
            raise

    def sendall(self, channel: paramiko.Channel, data: bytes, sendfunc: Callable[[bytes], int]) -> int:
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

    def close_session_with_status(self, channel: paramiko.Channel, status: Optional[int]) -> None:
        # pylint: disable=protected-access
        if channel.closed:
            return

        if not channel.eof_received:
            message = Message()
            message.add_byte(cMSG_CHANNEL_EOF)
            message.add_int(channel.remote_chanid)
            channel.transport._send_user_message(message)  # type: ignore

            if status is not None and self.session.scp_channel is not None:
                self.session.scp_channel.send_exit_status(status)

            message = Message()
            message.add_byte(cMSG_CHANNEL_REQUEST)
            message.add_int(channel.remote_chanid)
            message.add_string('eow@openssh.com')
            message.add_boolean(False)
            channel.transport._send_user_message(message)  # type: ignore

        message = Message()
        message.add_byte(cMSG_CHANNEL_CLOSE)
        message.add_int(channel.remote_chanid)
        channel.transport._send_user_message(message)  # type: ignore

        channel._unlink()  # type: ignore

        super().close_session(channel)
        logging.debug("[chan %d] SCP closed", channel.get_id())


class SCPForwarder(SCPBaseForwarder):
    """forwards a file from or to the remote server
    """

    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super().__init__(session)

        self.await_response = False
        self.bytes_remaining = 0
        self.bytes_to_write = 0

        self.file_command: Optional[str] = None
        self.file_mode: Optional[str] = None
        self.file_size: int = 0
        self.file_name: str = ''

        self.got_c_command = False

    def handle_command(self, traffic: bytes) -> bytes:
        self.got_c_command = False
        command = traffic.decode('utf-8')

        match_c_command = re.match(r"([CD])([0-7]{4})\s([0-9]+)\s(.*)\n", command)
        if not match_c_command:
            match_e_command = re.match(r"(E)\n", command)
            if match_e_command:
                logging.debug("got command %s", command.strip())
            match_t_command = re.match(r"(T)([0-9]+)\s([0-9]+)\s([0-9]+)\s([0-9]+)\n", command)
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

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        if self.session.scp_command.startswith(b'scp'):
            return self.handle_scp(traffic)
        if self.session.scp_command.startswith(b"mosh-server"):
            return handle_mosh(self.session, traffic, isclient)
        return traffic
