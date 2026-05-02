import logging
import time

import paramiko

from sshmitm.forwarders.base import BaseForwarder


class SSHBaseForwarder(BaseForwarder):  # pylint: disable=abstract-method
    """Specifies the interface responsible for managing SSH terminal sessions, including shell interaction and command execution."""

    @property
    def client_channel(self) -> paramiko.Channel | None:
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

        # store the remote channel to the ssh server in the current session
        self.session.ssh.remote_channel = self.server_channel

        if self.session.ssh.pty_kwargs:
            self.server_channel.get_pty(**self.session.ssh.pty_kwargs)
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
            buf = self.handle_client_data(buf)
            self.server_channel.sendall(buf)

    def forward_stdout(self) -> None:
        if self.server_channel.recv_ready():
            buf: bytes = self.server_channel.recv(self.BUF_LEN)
            buf = self.handle_server_data(buf)
            if self.client_channel is not None:
                self.client_channel.sendall(buf)

    def forward_extra(self) -> None:
        pass

    def forward_stderr(self) -> None:
        if self.server_channel.recv_stderr_ready():
            buf: bytes = self.server_channel.recv_stderr(self.BUF_LEN)
            buf = self.handle_server_error(buf)
            if self.client_channel is not None:
                self.client_channel.sendall_stderr(buf)

    def handle_client_data(self, data: bytes) -> bytes:
        return data

    def handle_server_data(self, data: bytes) -> bytes:
        return data

    def handle_server_error(self, data: bytes) -> bytes:
        return data
