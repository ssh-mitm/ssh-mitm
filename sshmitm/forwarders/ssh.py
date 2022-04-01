import logging
import time
from typing import (
    TYPE_CHECKING
)

from typeguard import typechecked

from sshmitm.forwarders.base import BaseForwarder
import sshmitm

if TYPE_CHECKING:
    from sshmitm.session import Session


class SSHBaseForwarder(BaseForwarder):
    pass


class SSHForwarder(SSHBaseForwarder):
    """forwards the terminal session to the remote server without modification
    """

    @typechecked
    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super(SSHForwarder, self).__init__(session)

    @typechecked
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

                if self.session.ssh_channel is not None and self._closed(self.session.ssh_channel):
                    self.server_channel.close()
                    self.close_session(self.session.ssh_channel)
                    break
                if self._closed(self.server_channel) and self.session.ssh_channel is not None:
                    self.close_session(self.session.ssh_channel)
                    break
                if self.server_channel.exit_status_ready():
                    self.server_channel.recv_exit_status()
                    if self.session.ssh_channel is not None:
                        self.close_session(self.session.ssh_channel)
                    break
                if self.session.ssh_channel is not None and self.session.ssh_channel.exit_status_ready():
                    self.session.ssh_channel.recv_exit_status()
                    if self.session.ssh_channel is not None:
                        self.close_session(self.session.ssh_channel)
                    break
                time.sleep(0.01)
        except Exception:
            logging.exception('error processing ssh session!')
            raise

    @typechecked
    def forward_stdin(self) -> None:
        if self.session.ssh_channel is not None and self.session.ssh_channel.recv_ready():
            buf: bytes = self.session.ssh_channel.recv(self.BUF_LEN)
            buf = self.stdin(buf)
            self.server_channel.sendall(buf)

    @typechecked
    def forward_stdout(self) -> None:
        if self.server_channel.recv_ready():
            buf: bytes = self.server_channel.recv(self.BUF_LEN)
            buf = self.stdout(buf)
            if self.session.ssh_channel is not None:
                self.session.ssh_channel.sendall(buf)

    @typechecked
    def forward_extra(self) -> None:
        pass

    @typechecked
    def forward_stderr(self) -> None:
        if self.server_channel.recv_stderr_ready():
            buf: bytes = self.server_channel.recv_stderr(self.BUF_LEN)
            buf = self.stderr(buf)
            if self.session.ssh_channel is not None:
                self.session.ssh_channel.sendall_stderr(buf)

    @typechecked
    def stdin(self, text: bytes) -> bytes:
        return text

    @typechecked
    def stdout(self, text: bytes) -> bytes:
        return text

    @typechecked
    def stderr(self, text: bytes) -> bytes:
        return text
