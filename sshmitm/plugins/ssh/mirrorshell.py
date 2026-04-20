import logging
import os
import select
import socket
import threading
import time
from typing import TYPE_CHECKING

import paramiko
from colored.colored import attr, fg

from sshmitm.forwarders.ssh import SSHForwarder
from sshmitm.logger import Colors
from sshmitm.plugins.ssh.terminallogs import ScriptLogFormat, TerminalLogFormat

if TYPE_CHECKING:
    import sshmitm


class InjectServer(paramiko.ServerInterface):
    def __init__(self, server_channel: paramiko.channel.Channel) -> None:
        self.server_channel = server_channel
        self.injector_channel: paramiko.channel.Channel | None = None

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
    """Mirror an SSH shell session to a second client (live session monitoring and injection)

    This plugin opens a secondary SSH listener on a random port for each intercepted session.
    A second client (e.g. a security analyst) can connect to that port with a plain ``ssh``
    command and observe the session in real time.  The mirror client can also type into the
    terminal - keystrokes are forwarded to the remote server as if they came from the
    original user.

    **Usage example**

    Start SSH-MITM with the mirror-shell plugin::

        ssh-mitm server --ssh-forwarder sshmitm.plugins.ssh.mirrorshell.SSHMirrorForwarder

    When a client connects, SSH-MITM prints a connection hint similar to::

        [i] created mirrorshell on port 34521. connect with: ssh -p 34521 127.0.0.1

    Connect from a second terminal to observe (and optionally interact with) the session::

        ssh -p 34521 127.0.0.1

    **Parameters**

    ``--ssh-mirrorshell-net <address>``
        Local address or interface on which the injector SSH listener is bound.
        Defaults to ``0.0.0.0`` when not specified.  Set this to ``127.0.0.1`` to
        restrict access to the local machine only.

    ``--ssh-mirrorshell-key <path>``
        Path to an RSA private key file used as the host key for the injector SSH
        server.  When omitted, a temporary 2048-bit RSA key is generated for every
        session.  Providing a fixed key avoids SSH host-key-changed warnings when
        reconnecting.

    ``--store-ssh-session``
        Record the complete terminal session (stdin, stdout, and stderr) to disk in
        *scriptreplay* format.  Requires ``--log-dir`` to be set so that SSH-MITM
        knows where to write the log files.

    ``--ssh-terminal-log-formatter script``
        Select the terminal log format.  Currently the only supported value is
        ``script``, which produces files compatible with the ``scriptreplay`` tool.

    **Notes**

    * Only one mirror client can be connected per session at a time.  A new
      connection replaces the previous one.
    * The mirror connection uses no authentication - any client that can reach the
      listener port can connect.  Bind to a restricted interface
      (``--ssh-mirrorshell-net 127.0.0.1``) when running in untrusted environments.
    * Session recordings are stored under ``<log-dir>/<session-id>/terminal_sessions/``
      and consist of three files per session: ``ssh_in_*.log``, ``ssh_out_*.log``, and
      ``ssh_time_*.log``.  Play back a recording with::

          scriptreplay ssh_time_<ts>.log ssh_out_<ts>.log
    """

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

        self.sessionlog: TerminalLogFormat | None = None
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
        self.inject_server: InjectServer | None = None

        self.injector_client_sock: socket.socket | None = None

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
                    except OSError:
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
