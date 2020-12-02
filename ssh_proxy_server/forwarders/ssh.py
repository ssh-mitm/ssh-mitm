import datetime
import logging
import os
import queue
import select
import socket
import tempfile
import threading
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


class SSHInjectableForwarder(SSHForwarder):

    @classmethod
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--ssh-injector-net',
            dest='ssh_injector_net',
            default='127.0.0.1',
            help='local address/interface where injector sessions are served'
        )
        cls.PARSER.add_argument(
            '--ssh-injector-port',
            dest='ssh_injector_port',
            default=0,
            type=int,
            help='local port where injector sessions are served'
        )

    def __init__(self, session):
        super(SSHInjectableForwarder, self).__init__(session)
        self.injector_ip = self.args.ssh_injector_net
        self.injector_port = self.args.ssh_injector_port
        self.injector_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            if self.injector_sock.connect_ex((self.injector_ip, self.injector_port)) == 0:
                self.injector_port += 1
            else:
                self.injector_sock.bind((self.injector_ip, self.injector_port))
                break
        self.injector_sock.listen(5)

        self.queue = queue.Queue()
        self.injector_shells = []
        thread = threading.Thread(target=self.injector_connect)
        thread.start()
        self.conn_thread = thread
        logging.info("creating ssh injector shell %s, connect with telnet", self.injector_sock.getsockname())

    def injector_connect(self):
        try:
            while self.session.running:
                readable = select.select([self.injector_sock], [], [])[0]
                if len(readable) == 1 and readable[0] is self.injector_sock:
                    client, addr = self.injector_sock.accept()
                    logging.info("injector shell opened from %s", str(addr))
                    injector_shell = threading.Thread(target=self.injector_session, args=(client,))
                    injector_shell.start()
                    self.injector_shells.append(injector_shell)
        except Exception as e:
            logging.warning("injector shell suffered an unexpected error")
            logging.exception(e)
            self.close_session(self.channel)

    def injector_session(self, client_sock):    # Exception handling
        with client_sock as sock:
            while True:
                data = sock.recv(self.BUF_LEN)
                self.queue.put(data)
                time.sleep(0.3)

    def forward_extra(self):
        if not self.server_channel.recv_ready() and not self.session.ssh_channel.recv_ready() and not self.queue.empty():
            msg = self.queue.get()
            self.server_channel.sendall(msg)
            self.queue.task_done()

    def close_session(self, channel):
        super().close_session(channel)
        logging.info("closing injector shell %s", self.injector_sock.getsockname())
        self.injector_sock.close()
        self.conn_thread.join()
        for shell in self.injector_shells:
            shell.join()
