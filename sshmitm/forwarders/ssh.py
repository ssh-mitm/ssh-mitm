import logging
import time
from typing import Optional

import paramiko

from sshmitm.forwarders.base import BaseForwarder


class SSHBaseForwarder(BaseForwarder):  # pylint: disable=abstract-method
    @property
    def client_channel(self) -> Optional[paramiko.Channel]:
        return self.session.ssh_channel

    def check_if_channels_are_closed(self) -> bool:
        if self.client_channel is not None and self._closed(self.client_channel):
            self.server_channel.close()
            self.close_session(self.client_channel)
            return True
        if self._closed(self.server_channel) and self.client_channel is not None:
            self.close_session(self.client_channel)
            return True
        if self.server_channel.exit_status_ready():
            self.server_channel.recv_exit_status()
            if self.client_channel is not None:
                self.close_session(self.client_channel)
            return True
        if self.client_channel is not None and self.client_channel.exit_status_ready():
            self.client_channel.recv_exit_status()
            if self.client_channel is not None:
                self.close_session(self.client_channel)
            return True
        return False


class SSHForwarder(SSHBaseForwarder):
    """forwards the terminal session to the remote server without modification"""

    def forward(self) -> None:
        time.sleep(0.1)

        if self.session.ssh_pty_kwargs:
            self.server_channel.get_pty(**self.session.ssh_pty_kwargs)
        self.server_channel.invoke_shell()

        try:
            while self.session.running:
                # forward stdout <-> stdin und stderr <-> stderr
                self.forward_stdin()
                self.forward_stdout()
                self.forward_extra()
                self.forward_stderr()

                if self.check_if_channels_are_closed():
                    break

                time.sleep(0.01)
        except Exception:
            logging.exception("error processing ssh session!")
            raise

    def forward_stdin(self) -> None:
        if self.client_channel is not None and self.client_channel.recv_ready():
            buf: bytes = self.client_channel.recv(self.BUF_LEN)
            buf = self.stdin(buf)
            self.server_channel.sendall(buf)

    def forward_stdout(self) -> None:
        if self.server_channel.recv_ready():
            buf: bytes = self.server_channel.recv(self.BUF_LEN)
            buf = self.stdout(buf)
            if self.client_channel is not None:
                self.client_channel.sendall(buf)

    def forward_extra(self) -> None:
        pass

    def forward_stderr(self) -> None:
        if self.server_channel.recv_stderr_ready():
            buf: bytes = self.server_channel.recv_stderr(self.BUF_LEN)
            buf = self.stderr(buf)
            if self.client_channel is not None:
                self.client_channel.sendall_stderr(buf)

    def stdin(self, text: bytes) -> bytes:
        return text

    def stdout(self, text: bytes) -> bytes:
        return text

    def stderr(self, text: bytes) -> bytes:
        return text
