import logging
import os
import time
from typing import TYPE_CHECKING, ClassVar

import paramiko

from sshmitm.apps.mosh.proxy import handle_mosh
from sshmitm.forwarders.exec import ExecHandlerBasePlugin
from sshmitm.plugins.ssh.terminallogs import (
    AsciinemLogFormat,
    ScriptLogFormat,
    TerminalLogFormat,
)

if TYPE_CHECKING:
    import sshmitm


class MoshForwarder(ExecHandlerBasePlugin):
    """Forwarder for MOSH (Mobile Shell) sessions.

    Executes the mosh-server command, waits for the MOSH CONNECT handshake
    to complete (server channel closes after sending it), then reads the
    buffered response and rewrites the port to point at the UDP proxy.
    """

    command_prefix: ClassVar[bytes] = b"mosh-server"
    disable_pty: ClassVar[bool] = True
    disable_ssh: ClassVar[bool] = True

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--store-mosh-session",
            dest="store_mosh_session",
            action="store_true",
            help="record MOSH terminal session to disk",
        )
        plugin_group.add_argument(
            "--mosh-terminal-log-formatter",
            dest="mosh_terminal_log_formatter",
            choices=["script", "asciinema"],
            default="script",
            help="terminal log format for captured MOSH session (default: script)",
        )

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session)
        self._mosh_sessionlog: TerminalLogFormat | None = None
        self._mosh_sessionlog_initialized: bool = False

    def _get_mosh_sessionlog(self) -> TerminalLogFormat | None:
        if self._mosh_sessionlog_initialized:
            return self._mosh_sessionlog
        self._mosh_sessionlog_initialized = True
        if not self.args.store_mosh_session or not self.session.session_log_dir:
            return None
        try:
            log_dir = os.path.join(self.session.session_log_dir, "terminal_sessions")
            formatter = (
                getattr(self.args, "mosh_terminal_log_formatter", None) or "script"
            )
            if formatter == "asciinema":
                self._mosh_sessionlog = AsciinemLogFormat(
                    log_dir, prefix="mosh_session"
                )
            else:
                self._mosh_sessionlog = ScriptLogFormat(log_dir, prefix="mosh_session")
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Error creating MOSH session log")
        return self._mosh_sessionlog

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return self.session.scp_channel

    @property
    def _forwarded_command(self) -> bytes:
        return self.session.scp.command

    def handle_client_data(self, data: bytes) -> bytes:
        return handle_mosh(self.session, data, True)

    def handle_server_data(self, data: bytes) -> bytes:
        return handle_mosh(
            self.session, data, False, sessionlog=self._get_mosh_sessionlog()
        )

    def forward(self) -> None:
        self.server_channel.exec_command(self.session.scp.command)  # nosec
        while not self._closed(self.server_channel):
            time.sleep(1)
        self._run_traffic_loop()
