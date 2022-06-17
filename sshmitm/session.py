import logging
import threading
from uuid import uuid4
import os
import socket

from typing import (
    TYPE_CHECKING,
    cast,
    Any,
    Dict,
    Optional,
    Union,
    Tuple,
    Text,
    Type
)

from enhancements.modules import BaseModule

from colored.colored import stylize, fg, attr  # type: ignore
import paramiko
from paramiko.pkey import PKey
from rich._emoji_codes import EMOJI

from paramiko import Transport
from paramiko.ssh_exception import ChannelException
from typeguard import typechecked

import sshmitm
from sshmitm.forwarders.agent import AgentProxy
from sshmitm.interfaces.server import BaseServerInterface, ProxySFTPServer
from sshmitm.plugins.session import key_negotiation

if TYPE_CHECKING:
    from sshmitm.server import SSHProxyServer


class BaseSession(BaseModule):
    pass


class Session(BaseSession):

    CIPHERS = None

    @classmethod
    @typechecked
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--session-log-dir',
            dest='session_log_dir',
            help='directory to store ssh session logs'
        )

    @typechecked
    def __init__(
        self,
        proxyserver: 'sshmitm.server.SSHProxyServer',
        client_socket: socket.socket,
        client_address: Union[Tuple[Text, int], Tuple[Text, int, int, int]],
        authenticator: Type['sshmitm.authentication.Authenticator'],
        remoteaddr: Union[Tuple[Text, int], Tuple[Text, int, int, int]]
    ) -> None:
        super().__init__()
        self.sessionid = uuid4()
        logging.info(f"{EMOJI['information']} session {stylize(self.sessionid, fg('light_blue') + attr('bold'))} created")
        self._transport: Optional[paramiko.Transport] = None

        self.channel = None

        self.proxyserver: 'sshmitm.server.SSHProxyServer' = proxyserver
        self.client_socket = client_socket
        self.client_address = client_address
        self.name = f"{client_address}->{remoteaddr}"
        self.closed = False

        self.agent_requested: threading.Event = threading.Event()

        self.ssh_requested: bool = False
        self.ssh_channel: Optional[paramiko.Channel] = None
        self.ssh_client: Optional[sshmitm.clients.ssh.SSHClient] = None
        self.ssh_pty_kwargs = None

        self.scp_requested: bool = False
        self.scp_channel = None
        self.scp_command: bytes = b''

        self.sftp_requested: bool = False
        self.sftp_channel = None
        self.sftp_client: Optional[sshmitm.clients.sftp.SFTPClient] = None
        self.sftp_client_ready = threading.Event()

        self.username: str = ''
        self.username_provided: Optional[str] = None
        self.password: Optional[str] = None
        self.password_provided: Optional[str] = None
        self.socket_remote_address = remoteaddr
        self.remote_address: Tuple[Optional[Text], Optional[int]] = (None, None)
        self.remote_address_reachable: bool = True
        self.remote_key: Optional[PKey] = None
        self.accepted_key: Optional[PKey] = None
        self.agent: Optional[AgentProxy] = None
        self.authenticator: 'sshmitm.authentication.Authenticator' = authenticator(self)

        self.env_requests: Dict[bytes, bytes] = {}
        self.session_log_dir: Optional[str] = self.get_session_log_dir()

    @typechecked
    def get_session_log_dir(self) -> Optional[str]:
        if not self.args.session_log_dir:
            return None
        session_log_dir = os.path.expanduser(self.args.session_log_dir)
        return os.path.join(
            session_log_dir,
            str(self.sessionid)
        )

    @property
    def running(self) -> bool:
        session_channel_open: bool = True
        ssh_channel_open: bool = False
        scp_channel_open: bool = False

        if self.channel is not None:
            session_channel_open = not self.channel.closed
        if self.ssh_channel is not None:
            ssh_channel_open = not self.ssh_channel.closed
        if self.scp_channel is not None:
            scp_channel_open = not self.scp_channel.closed if self.scp_channel else False
        open_channel_exists = session_channel_open or ssh_channel_open or scp_channel_open

        return_value = self.proxyserver.running and open_channel_exists and not self.closed
        return return_value

    @property
    def transport(self) -> paramiko.Transport:
        if self._transport is None:
            self._transport = Transport(self.client_socket)
            key_negotiation.handle_key_negotiation(self)
            if self.CIPHERS:
                if not isinstance(self.CIPHERS, tuple):
                    raise ValueError('ciphers must be a tuple')
                self._transport.get_security_options().ciphers = self.CIPHERS
            host_key: Optional[PKey] = self.proxyserver.host_key
            if host_key is not None:
                self._transport.add_server_key(host_key)
            self._transport.set_subsystem_handler('sftp', ProxySFTPServer, self.proxyserver.sftp_interface, self)

        return self._transport

    @typechecked
    def _start_channels(self) -> bool:
        # create client or master channel
        if self.ssh_client:
            self.sftp_client_ready.set()
            return True

        if not self.agent or self.authenticator.REQUEST_AGENT_BREAKIN:
            try:
                if self.agent_requested.wait(1) or self.authenticator.REQUEST_AGENT_BREAKIN:
                    self.agent = AgentProxy(self.transport)
            except ChannelException:
                logging.error("Breakin not successful! Closing ssh connection to client")
                self.agent = None
                self.close()
                return False
        # Connect method start
        if not self.agent:
            if self.username_provided is None:
                logging.error("No username proviced during login!")
                return False
            return self.authenticator.auth_fallback(self.username_provided) == paramiko.common.AUTH_SUCCESSFUL

        if self.authenticator.authenticate(store_credentials=False) != paramiko.common.AUTH_SUCCESSFUL:
            if self.username_provided is None:
                logging.error("No username proviced during login!")
                return False
            if self.authenticator.auth_fallback(self.username_provided) == paramiko.common.AUTH_SUCCESSFUL:
                return True            
            self.transport.close()
            return False

        # Connect method end
        if not self.scp_requested and not self.ssh_requested and not self.sftp_requested:
            if self.transport.is_active():
                self.transport.close()
                return False

        self.sftp_client_ready.set()
        return True

    @typechecked
    def start(self) -> bool:
        event = threading.Event()
        self.transport.start_server(
            event=event,
            server=self.proxyserver.authentication_interface(self)
        )

        while not self.channel:
            self.channel = self.transport.accept(0.5)
            if not self.running:
                self.transport.close()
                return False

        if not self.channel:
            logging.error('(%s) session error opening channel!', self)
            self.transport.close()
            return False

        # wait for authentication
        event.wait()

        if not self.transport.is_active():
            return False

        self.proxyserver.client_tunnel_interface.setup(self)

        if not self._start_channels():
            return False

        logging.info(f"{EMOJI['information']} {stylize(self.sessionid, fg('light_blue') + attr('bold'))} - session started")
        return True

    @typechecked
    def close(self) -> None:
        if self.agent:
            self.agent.close()
            logging.debug("(%s) session agent cleaned up", self)
        if self.ssh_client:
            logging.debug("(%s) closing ssh client to remote", self)
            if self.ssh_client.transport:
                self.ssh_client.transport.close()
            # With graceful exit the completion_event can be polled to wait, well ..., for completion
            # it can also only be a graceful exit if the ssh client has already been established
            if self.transport.completion_event is not None:
                if self.transport.completion_event.is_set() and self.transport.is_active():
                    self.transport.completion_event.clear()
                    while self.transport.is_active():
                        if self.transport.completion_event.wait(0.1):
                            break
        if self.transport.server_object is not None:
            for f in cast(BaseServerInterface, self.transport.server_object).forwarders:
                f.close()
                f.join()
        self.transport.close()
        logging.info(f"{EMOJI['information']} session {stylize(self.sessionid, fg('light_blue') + attr('bold'))} closed")
        logging.debug(f"({self}) session closed")
        self.closed = True

    @typechecked
    def __str__(self) -> str:
        return self.name

    @typechecked
    def __enter__(self) -> 'Session':
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        logging.debug("(%s) session exited", self)
        self.close()
