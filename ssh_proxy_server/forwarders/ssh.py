import datetime
import logging
import os
import tempfile
import time

import pytz

from ssh_proxy_server.forwarders.base import BaseForwarder


class SSHBaseForwarder(BaseForwarder):
    pass


class SSHForwarder(SSHBaseForwarder):

    def __init__(self, session):
        super(SSHForwarder, self).__init__(session)

    def forward(self):
        time.sleep(0.1)

        if self.session.sshPtyKArgs:
            self.server_channel.get_pty(**self.session.sshPtyKArgs)
        self.server_channel.invoke_shell()

        try:
            while self.session.running:
                # forward stdout <-> stdin und stderr <-> stderr
                if self.session.ssh_channel.recv_ready():
                    buf = self.session.ssh_channel.recv(self.BUF_LEN)
                    buf = self.stdin(buf)
                    self.server_channel.sendall(buf)
                if self.server_channel.recv_ready():
                    buf = self.server_channel.recv(self.BUF_LEN)
                    buf = self.stdout(buf)
                    self.session.ssh_channel.sendall(buf)
                if self.server_channel.recv_stderr_ready():
                    buf = self.server_channel.recv_stderr(self.BUF_LEN)
                    buf = self.stderr(buf)
                    self.session.ssh_channel.sendall_stderr(buf)

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

    def close_session(self, channel):
        channel.get_transport().close()
        logging.info("session closed")

    def stdin(self, text):
        return text

    def stdout(self, text):
        return text

    def stderr(self, text):
        return text


class SSHLogForwarder(SSHForwarder):

    @classmethod
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--ssh-log-dir',
            dest='ssh_log_dir',
            required=True,
            help='directory to store ssh session logs'
        )

    def __init__(self, session):
        super().__init__(session)
        self.timestamp = None

        self.logdir = None
        if self.args.ssh_log_dir:
            self.logdir = os.path.join(
                self.args.ssh_log_dir,
                "{}_{}@{}".format(
                    str(time.time()).split('.')[0],
                    self.session.username,
                    self.session.remote_address[0]
                )
            )
        else:
            logging.error('no --ssh-log-dir parameter given! - Logging disabled!')

        self.fileIn, self.fileOut, self.timeingfile = self._initFiles()

    def _initFiles(self):
        if not self.logdir:
            return None, None, None

        os.makedirs(self.logdir, exist_ok=True)
        timecomponent = str(time.time()).split('.')[0]

        fileIn = tempfile.NamedTemporaryFile(
            prefix='ssh_in_{}_'.format(timecomponent),
            suffix='.log',
            dir=self.logdir,
            delete=False
        )

        fileOut = tempfile.NamedTemporaryFile(
            prefix='ssh_out_{}_'.format(timecomponent),
            suffix='.log',
            dir=self.logdir,
            delete=False
        )
        fileOut.write(
            "Session started on {}\n".format(
                datetime.datetime.utcnow().replace(
                    tzinfo=pytz.utc
                ).strftime("%a %d %b %Y %H:%M:%S %Z")
            ).encode()
        )
        fileOut.flush()

        timeingfile = tempfile.NamedTemporaryFile(
            prefix='ssh_time_{}_'.format(timecomponent),
            suffix='.log',
            dir=self.logdir,
            delete=False
        )
        return fileIn, fileOut, timeingfile

    def close_session(self, channel):
        super().close_session(channel)
        if self.logdir:
            self.timeingfile.close()
            self.fileOut.close()
            self.fileIn.close()

    def stdin(self, text):
        if self.logdir:
            self.fileIn.write(text)
            self.fileIn.flush()
        return text

    def stdout(self, text):
        if self.logdir:
            self.fileOut.write(text)
            self.fileOut.flush()
            self.write_timingfile(text)
        return text

    def stderr(self, text):
        if self.logdir:
            self.fileOut.write(text)
            self.fileOut.flush()
            self.write_timingfile(text)
        return text

    def write_timingfile(self, text):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now()
        oldtime = self.timestamp
        self.timestamp = datetime.datetime.now()
        diff = self.timestamp - oldtime
        self.timeingfile.write("{}.{} {}\n".format(diff.seconds, diff.microseconds, len(text)).encode())
        self.timeingfile.flush()


class NoShellForwarder(SSHForwarder):
    def forward(self):
        self.session.channel.send_stderr('Terminalzugriff nicht erlaubt!\r\n')
        self.session.channel.send_stderr('Verbindung kann als Masterchannel genutzt werden.\r\n')
        self.session.channel.send_stderr('Beenden mit strg+c!\r\n')
        while self.session.running:
            if self.session.channel.recv_ready():
                if b'\x03' in self.session.channel.recv(1024):  # Ctrl + C
                    self.session.channel.send_stderr('Warte bis alle Sessions beendet wurden!\r\n')
                    self.session.transport.close()
                    break
            time.sleep(0.5)
