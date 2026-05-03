import inspect
import logging
import re
import time
import warnings
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any, ClassVar

import paramiko

from sshmitm.forwarders.exec import ExecForwarder, ExecHandlerBasePlugin

if TYPE_CHECKING:
    import sshmitm


@dataclass
class ExecHandlerEntry:
    """Registry entry for a command-prefix-based exec handler."""

    handler: type[Any]
    name: str = ""
    disable_pty: bool = False
    disable_ssh: bool = False


class SCPBaseForwarder(ExecForwarder):
    """Defines the interface used for handling SCP (Secure Copy Protocol) file transfers, including uploads and downloads."""

    _exec_handlers: ClassVar[dict[bytes, ExecHandlerEntry]] = {}
    _handlers_loaded: ClassVar[bool] = False

    @classmethod
    def register_exec_handler(
        cls,
        prefix: bytes,
        handler: type[Any],
        *,
        name: str = "",
        disable_pty: bool = False,
        disable_ssh: bool = False,
    ) -> None:
        cls._exec_handlers[prefix] = ExecHandlerEntry(
            handler=handler,
            name=name or handler.__name__,
            disable_pty=disable_pty,
            disable_ssh=disable_ssh,
        )

    @staticmethod
    def _is_handler_allowed(
        name: str,
        enabled: list[str],
        disabled: list[str],
    ) -> bool:
        enabled_all = "ALL" in enabled
        enabled_none = "NONE" in enabled
        disabled_all = "ALL" in disabled
        disabled_none = "NONE" in disabled

        if enabled_none:
            return False

        if enabled_all and disabled_all:
            warnings.warn(
                "enabled_exec_handlers=ALL and disabled_exec_handlers=ALL: no handlers will run",
                stacklevel=3,
            )
            return False

        if disabled_all:
            return name in enabled

        if enabled_all:
            return disabled_none or name not in disabled

        return name in enabled and (disabled_none or name not in disabled)

    @classmethod
    def get_exec_handler(
        cls,
        command: bytes,
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
    ) -> ExecHandlerEntry | None:
        cls._ensure_handlers_loaded()
        _enabled = enabled if enabled is not None else ["ALL"]
        _disabled = disabled if disabled is not None else ["NONE"]
        for prefix, entry in cls._exec_handlers.items():
            if command.startswith(prefix):
                if cls._is_handler_allowed(entry.name, _enabled, _disabled):
                    return entry
                return None
        return None

    @classmethod
    def _ensure_handlers_loaded(cls) -> None:
        if cls._handlers_loaded:
            return
        cls._handlers_loaded = True
        cls.load_exec_handlers()

    @classmethod
    def load_exec_handlers(cls) -> None:
        """Load exec handlers registered via the 'sshmitm.ExecHandler' entry point group."""
        try:
            for ep in entry_points(group="sshmitm.ExecHandler"):
                try:
                    handler_class = ep.load()
                    if inspect.isclass(handler_class) and issubclass(handler_class, ExecHandlerBasePlugin):
                        cls._exec_handlers[handler_class.command_prefix] = ExecHandlerEntry(
                            handler=handler_class,
                            name=ep.name,
                            disable_pty=handler_class.disable_pty,
                            disable_ssh=handler_class.disable_ssh,
                        )
                except Exception:  # pylint: disable=broad-exception-caught
                    logging.exception("Failed to load exec handler %s", ep.name)
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Failed to load exec handlers")

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
    """forwards a file from or to the remote server"""

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

    def handle_command(self, traffic: bytes) -> bytes:
        self.got_c_command = False
        command = traffic.decode("utf-8")

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
            return traffic

        logging.debug("got command %s", command.strip())
        self.got_c_command = True

        self.file_command = match_c_command[1]
        self.file_mode = match_c_command[2]
        self.bytes_remaining = self.file_size = int(match_c_command[3])
        self.file_name = match_c_command[4]

        self.await_response = True
        return traffic

    def process_data(self, traffic: bytes) -> bytes:
        return traffic

    def process_response(self, traffic: bytes) -> bytes:
        return traffic

    def handle_scp(self, traffic: bytes) -> bytes:
        if self.await_response:
            self.await_response = False
            return self.process_response(traffic)

        if self.bytes_remaining == 0 and not self.got_c_command:
            return self.handle_command(traffic)

        self.got_c_command = False
        return self.process_data(traffic)

    def process_command_data(
        self, command: bytes, traffic: bytes, isclient: bool
    ) -> bytes:
        del command
        del isclient
        return traffic

    def handle_client_data(self, traffic: bytes) -> bytes:
        if self.session.scp.command.startswith(b"scp"):
            return self.handle_scp(traffic)
        return self.process_command_data(self.session.scp.command, traffic, True)

    def handle_server_data(self, traffic: bytes) -> bytes:
        if self.session.scp.command.startswith(b"scp"):
            return self.handle_scp(traffic)
        return self.process_command_data(self.session.scp.command, traffic, False)
