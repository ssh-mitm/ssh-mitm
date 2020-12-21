import datetime
import logging
import os
import tempfile
import time

import pytz

from ssh_proxy_server.forwarders.ssh import SSHForwarder


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
        self.args.ssh_log_dir = os.path.expanduser(self.args.ssh_log_dir)
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
