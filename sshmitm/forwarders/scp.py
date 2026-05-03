import logging
import re
import time
from typing import TYPE_CHECKING

import paramiko

from sshmitm.exec_handlers import ExecHandlerRegistry
from sshmitm.forwarders.exec import ExecForwarder

if TYPE_CHECKING:
    import sshmitm


class SCPBaseForwarder(ExecHandlerRegistry, ExecForwarder):
    """Defines the interface used for handling SCP (Secure Copy Protocol) file transfers, including uploads and downloads."""

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return self.session.scp_channel

    @property
    def _forwarded_command(self) -> bytes:
        return self.session.scp.command

    def rewrite_scp_command(self, command: str) -> str:
        logging.info("got remote command: %s", command)
        return command

    def forward(self) -> None:
        # pylint: disable=protected-access
        if self.session.ssh.pty_kwargs is not None:
            self.server_channel.get_pty(**self.session.ssh.pty_kwargs)

        self.session.scp.command = self.rewrite_scp_command(
            self.session.scp.command.decode("utf8")
        ).encode()
        self.server_channel.exec_command(self.session.scp.command)  # nosec

        # Wait for SCP remote to remote auth, command exec and copy to finish
        if self.session.scp.command.decode("utf8").startswith("scp") and (
            self.session.scp.command.find(b" -t ") == -1
            and self.session.scp.command.find(b" -f ") == -1
        ):
            if self.client_channel is not None:
                logging.debug(
                    "[chan %d] Initiating SCP remote to remote",
                    self.client_channel.get_id(),
                )
                if self.session.auth.agent is None:
                    logging.warning(
                        "[chan %d] SCP remote to remote needs a forwarded agent",
                        self.client_channel.get_id(),
                    )
            while not self._closed(self.server_channel):
                time.sleep(1)

        self._run_traffic_loop()


class SCPForwarder(SCPBaseForwarder):
    """Transparent SCP plugin — forwards all data unchanged.

    This is the base class for all SCP plugins. Inherit from this class
    to implement custom SCP behaviour; override only the methods you need.
    """

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session)

        self.await_response = False
        self.bytes_remaining = 0
        self.bytes_to_write = 0

        self.file_command: str | None = None
        self.file_mode: str | None = None
        self.file_size: int = 0
        self.file_name: str = ""

        self.got_c_command = False

    def handle_command(self, data: bytes) -> bytes:
        self.got_c_command = False
        command = data.decode("utf-8")

        match_c_command = re.match(r"([CD])([0-7]{4})\s([0-9]+)\s(.*)\n", command)
        if not match_c_command:
            match_e_command = re.match(r"(E)\n", command)
            if match_e_command:
                logging.debug("got command %s", command.strip())
            match_t_command = re.match(
                r"(T)([0-9]+)\s([0-9]+)\s([0-9]+)\s([0-9]+)\n", command
            )
            if match_t_command:
                logging.debug("got command %s", command.strip())
            return data

        logging.debug("got command %s", command.strip())
        self.got_c_command = True

        self.file_command = match_c_command[1]
        self.file_mode = match_c_command[2]
        self.bytes_remaining = self.file_size = int(match_c_command[3])
        self.file_name = match_c_command[4]

        self.await_response = True
        return data

    def process_data(self, data: bytes) -> bytes:
        return data

    def process_response(self, data: bytes) -> bytes:
        return data

    def handle_scp(self, data: bytes) -> bytes:
        if self.await_response:
            self.await_response = False
            return self.process_response(data)

        if self.bytes_remaining == 0 and not self.got_c_command:
            return self.handle_command(data)

        self.got_c_command = False
        return self.process_data(data)

    def process_command_data(
        self, command: bytes, data: bytes, isclient: bool
    ) -> bytes:
        del command
        del isclient
        return data

    def handle_client_data(self, data: bytes) -> bytes:
        if self.session.scp.command.startswith(b"scp"):
            return self.handle_scp(data)
        return self.process_command_data(self.session.scp.command, data, True)

    def handle_server_data(self, data: bytes) -> bytes:
        if self.session.scp.command.startswith(b"scp"):
            return self.handle_scp(data)
        return self.process_command_data(self.session.scp.command, data, False)
