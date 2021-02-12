import logging
import time

from ssh_proxy_server.forwarders.base import BaseForwarder


class SSHBaseForwarder(BaseForwarder):
    pass


class SSHForwarder(SSHBaseForwarder):
    """forwards the terminal session to the remote server without modification
    """

    def __init__(self, session):
        super(SSHForwarder, self).__init__(session)

    def forward(self):
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

                if self._closed(self.session.ssh_channel):
                    self.server_channel.close()
                    self.close_session(self.session.ssh_channel)
                    break
                if self._closed(self.server_channel):
                    self.close_session(self.session.ssh_channel)
                    break
                if self.server_channel.exit_status_ready():
                    self.server_channel.recv_exit_status()
                    self.close_session(self.session.ssh_channel)
                    break
                if self.session.ssh_channel.exit_status_ready():
                    self.session.ssh_channel.recv_exit_status()
                    self.close_session(self.session.ssh_channel)
                    break
                time.sleep(0.01)
        except Exception:
            logging.exception('error processing ssh session!')
            raise

    def forward_stdin(self):
        if self.session.ssh_channel.recv_ready():
            buf = self.session.ssh_channel.recv(self.BUF_LEN)
            buf = self.stdin(buf)
            self.server_channel.sendall(buf)

    def forward_stdout(self):
        if self.server_channel.recv_ready():
            buf = self.server_channel.recv(self.BUF_LEN)
            buf = self.stdout(buf)
            self.session.ssh_channel.sendall(buf)

    def forward_extra(self):
        pass

    def forward_stderr(self):
        if self.server_channel.recv_stderr_ready():
            buf = self.server_channel.recv_stderr(self.BUF_LEN)
            buf = self.stderr(buf)
            self.session.ssh_channel.sendall_stderr(buf)

    def stdin(self, text):
        return text

    def stdout(self, text):
        return text

    def stderr(self, text):
        return text
