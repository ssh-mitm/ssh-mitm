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
            logging.debug("DEBUG: Client channel is closed")
            self.server_channel.close()
            self.close_session(self.client_channel)
            return True
        if self._closed(self.server_channel) and self.client_channel is not None:
            logging.debug("DEBUG: Server channel is closed")
            self.close_session(self.client_channel)
            return True
        if self.server_channel.exit_status_ready():
            exit_status = self.server_channel.recv_exit_status()
            logging.debug("DEBUG: Server channel exit status ready: %s", exit_status)
            if self.client_channel is not None:
                self.close_session(self.client_channel)
            return True
        if self.client_channel is not None and self.client_channel.exit_status_ready():
            exit_status = self.client_channel.recv_exit_status()
            logging.debug("DEBUG: Client channel exit status ready: %s", exit_status)
            if self.client_channel is not None:
                self.close_session(self.client_channel)
            return True
        return False


class SSHForwarder(SSHBaseForwarder):
    """forwards the terminal session to the remote server without modification"""

    def forward(self) -> None:
        logging.debug("DEBUG: SSHForwarder.forward() starting")
        time.sleep(0.1)

        # store the remote channel to the ssh server in the current session
        self.session.ssh_remote_channel = self.server_channel
        logging.debug("DEBUG: Remote channel stored: %s", self.server_channel)

        if self.session.ssh_pty_kwargs:
            logging.debug("DEBUG: Requesting PTY with kwargs: %s", self.session.ssh_pty_kwargs)
            try:
                self.server_channel.get_pty(**self.session.ssh_pty_kwargs)
                logging.debug("DEBUG: PTY request successful")
            except Exception as e:
                logging.error("DEBUG: PTY request failed: %s", e)
                return
        else:
            logging.debug("DEBUG: No PTY kwargs, skipping PTY request")
            
        logging.debug("DEBUG: Invoking shell on remote server")
        try:
            self.server_channel.invoke_shell()
            logging.debug("DEBUG: Shell invoke successful")
        except Exception as e:
            logging.error("DEBUG: Shell invoke failed: %s", e)
            return

        logging.debug("DEBUG: Entering forward loop, session.running=%s", self.session.running)
        try:
            loop_count = 0
            while self.session.running:
                loop_count += 1
                if loop_count % 100 == 0:  # Log every 100 iterations to avoid spam
                    logging.debug("DEBUG: Forward loop iteration %d, session still running", loop_count)
                
                # forward stdout <-> stdin und stderr <-> stderr
                self.forward_stdin()
                self.forward_stdout()
                self.forward_extra()
                self.forward_stderr()

                if self.check_if_channels_are_closed():
                    logging.debug("DEBUG: Channels are closed, breaking forward loop")
                    break

                time.sleep(0.01)
        except Exception:
            logging.exception("error processing ssh session!")
            raise
        finally:
            logging.debug("DEBUG: SSHForwarder.forward() ending")

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
