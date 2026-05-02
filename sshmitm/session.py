"""Session Class

The Session class provides the ability to start, manage, and close an interactive session between
a client and a server. It provides a convenient and exception-safe way to handle sessions in your application.

.. code-block:: python

    try:
        with Session(self, client, addr, self.authenticator, remoteaddr) as session:
            if session.start():
                while session.running:
                    # session is running
                    pass
            else:
                logging.warning("(%s) session not started", session)
    except Exception:
        logging.exception("error handling session creation")

This code creates a session object using the session_class method, and wraps it in a with statement.
The start method is then called on the session object. If the start method returns True, the session
is considered running and the running property of the session is checked in a while loop. If the start
method returns False, a warning message is logged indicating that the session was not started.
If any exceptions are raised during session creation, they are logged using the logging.exception method.
"""

import logging
import os
import socket
import threading
from dataclasses import dataclass, field
from threading import Condition
from types import TracebackType
from typing import TYPE_CHECKING, Any, Self, cast
from uuid import uuid4

import paramiko
from colored.colored import attr, fg
from paramiko import Transport
from paramiko.ssh_exception import ChannelException

from sshmitm.core.modules import SSHMITMBaseModule
from sshmitm.logger import THREAD_DATA
from sshmitm.moduleparser.colors import Colors

if TYPE_CHECKING:
    from paramiko.pkey import PKey

    import sshmitm
    import sshmitm.clients.netconf
    import sshmitm.clients.sftp
    import sshmitm.clients.ssh
    from sshmitm.forwarders.agent import AgentLocalSocket, AgentProxy
    from sshmitm.interfaces.server import BaseServerInterface
    from sshmitm.server import SSHProxyServer  # noqa: F401


@dataclass
class SSHState:
    requested: bool = False
    client: "sshmitm.clients.ssh.SSHClient | None" = field(default=None)
    client_auth_finished: bool = False
    client_created: Condition = field(default_factory=Condition)
    pty_kwargs: dict[str, Any] | None = None
    remote_channel: paramiko.Channel | None = None


@dataclass
class SCPState:
    requested: bool = False
    command: bytes = b""


@dataclass
class SFTPState:
    requested: bool = False
    channel: paramiko.Channel | None = None
    client: "sshmitm.clients.sftp.SFTPClient | None" = field(default=None)
    client_ready: threading.Event = field(default_factory=threading.Event)


@dataclass
class NetconfState:
    requested: bool = False
    command: bytes = b""
    client: "sshmitm.clients.netconf.NetconfClient | None" = field(default=None)
    client_ready: threading.Event = field(default_factory=threading.Event)


@dataclass
class AuthState:
    username: str = ""
    username_provided: str | None = None
    password: str | None = None
    password_provided: str | None = None
    remote_key: "PKey | None" = field(default=None)
    accepted_key: "PKey | None" = field(default=None)
    agent: "AgentProxy | None" = field(default=None)


@dataclass
class RemoteState:
    socket_address: "tuple[str, int] | tuple[str, int, int, int]"
    address: tuple[str | None, int | None] = field(default_factory=lambda: (None, None))
    address_reachable: bool = True


class BaseSession(SSHMITMBaseModule):
    """Sets the custom session class for SSH-MITM, controlling session behavior, logging, and interaction handling."""

    def __init__(self) -> None:
        super().__init__()
        self.sessionid = uuid4()

    def register_session_thread(self) -> None:
        THREAD_DATA.session = self


class Session(BaseSession):
    """Session Handler to store and manage active SSH sessions.

    :param proxyserver: Instance of 'sshmitm.server.SSHProxyServer' class
    :param client_socket: A socket instance representing the connection from the client
    :param client_address: Address information of the client
    :param authenticator: Type of the authentication class to be used
    :param remoteaddr: Remote address information
    """

    CIPHERS = None

    @classmethod
    def parser_arguments(cls) -> None:
        """
        Add an argument to the command line parser for session plugin.
        """
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--session-log-dir",
            dest="session_log_dir",
            help="directory to store ssh session logs",
        )

    def __init__(  # pylint: disable=too-many-arguments
        self,
        proxyserver: "sshmitm.server.SSHProxyServer",
        client_socket: socket.socket,
        client_address: tuple[str, int] | tuple[str, int, int, int],
        authenticator: type["sshmitm.authentication.Authenticator"],
        remoteaddr: tuple[str, int] | tuple[str, int, int, int],
        banner_name: str | None = None,
    ) -> None:
        """
        Initialize the class instance.

        :param proxyserver: Instance of 'sshmitm.server.SSHProxyServer' class
        :param client_socket: A socket instance representing the connection from the client
        :param client_address: Address information of the client
        :param authenticator: Type of the authentication class to be used
        :param remoteaddr: Remote address information
        """
        super().__init__()
        self.register_session_thread()
        logging.info(
            "%s session %s created",
            Colors.emoji("information"),
            Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
        )
        self._transport: paramiko.Transport | None = None
        self._active_channels: dict[str, paramiko.Channel] = {}

        self.channel: paramiko.Channel | None = None

        self.proxyserver: sshmitm.server.SSHProxyServer = proxyserver
        self.client_socket = client_socket
        self.client_address = client_address
        self.name = f"{client_address}->{remoteaddr}"
        self.closed = False

        self.agent_requested: threading.Event = threading.Event()

        self.ssh = SSHState()
        self.scp = SCPState()
        self.sftp = SFTPState()
        self.netconf = NetconfState()

        self.auth = AuthState()
        self.remote = RemoteState(socket_address=remoteaddr)
        self.authenticator: sshmitm.authentication.Authenticator = authenticator(self)

        self.env_requests: dict[bytes, bytes] = {}
        self.session_log_dir: str | None = self.get_session_log_dir()
        self.banner_name = banner_name

    def get_session_log_dir(self) -> str | None:
        """
        Returns the directory where the ssh session logs will be stored.

        :return: The directory path where the ssh session logs will be stored, or `None` if the directory is not specified.
        """
        if not self.args.session_log_dir:
            return None
        session_log_dir = os.path.expanduser(self.args.session_log_dir)
        return os.path.join(session_log_dir, str(self.sessionid))

    @property
    def ssh_channel(self) -> paramiko.Channel | None:
        return self._active_channels.get("ssh")

    @ssh_channel.setter
    def ssh_channel(self, value: paramiko.Channel | None) -> None:
        if value is None:
            self._active_channels.pop("ssh", None)
        else:
            self._active_channels["ssh"] = value

    @property
    def scp_channel(self) -> paramiko.Channel | None:
        return self._active_channels.get("scp")

    @scp_channel.setter
    def scp_channel(self, value: paramiko.Channel | None) -> None:
        if value is None:
            self._active_channels.pop("scp", None)
        else:
            self._active_channels["scp"] = value

    @property
    def netconf_channel(self) -> paramiko.Channel | None:
        return self._active_channels.get("netconf")

    @netconf_channel.setter
    def netconf_channel(self, value: paramiko.Channel | None) -> None:
        if value is None:
            self._active_channels.pop("netconf", None)
        else:
            self._active_channels["netconf"] = value

    @property
    def running(self) -> bool:
        """
        Returns the running state of the current session.

        :return: A boolean indicating whether the session is running or not
        """
        session_channel_open = self.channel is None or not self.channel.closed
        open_channel_exists = session_channel_open or any(
            not ch.closed for ch in self._active_channels.values()
        )
        return self.proxyserver.running and open_channel_exists and not self.closed

    @property
    def transport(self) -> paramiko.Transport:
        """
        Returns the type of transport being used by the current session.

        :return: A string representing the transport type
        """
        if self._transport is None:
            self._transport = Transport(self.client_socket)
            if self.banner_name:
                self.transport.local_version = f"SSH-2.0-{self.banner_name}"
            self.proxyserver.setup_transport_hooks(self)
            if self.CIPHERS:
                if not isinstance(self.CIPHERS, tuple):
                    msg = "ciphers must be a tuple"
                    raise ValueError(msg)
                self._transport.get_security_options().ciphers = self.CIPHERS
            host_key: PKey | None = self.proxyserver.host_key
            if host_key is not None:
                self._transport.add_server_key(host_key)
            self.proxyserver.register_subsystem_handlers(self._transport, self)

        return self._transport

    def _request_agent(self) -> bool:
        requested_agent = None
        if self.auth.agent is None or self.authenticator.REQUEST_AGENT_BREAKIN:
            try:
                if (
                    self.agent_requested.wait(1)
                    or self.authenticator.REQUEST_AGENT_BREAKIN
                ):
                    requested_agent = self.proxyserver.create_agent_proxy(self.transport)
                    logging.info(
                        "%s %s - successfully requested ssh-agent",
                        Colors.emoji("information"),
                        Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
                    )
                    if self.proxyserver.expose_agent_socket:
                        self._expose_agent_socket(requested_agent)
            except ChannelException:
                logging.info(
                    "%s %s - ssh-agent breakin not successfull!",
                    Colors.emoji("warning"),
                    Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
                )
                return False
        self.auth.agent = requested_agent or self.auth.agent
        return self.auth.agent is not None

    def _expose_agent_socket(self, agent: "AgentProxy") -> None:
        agent.local_socket = self.proxyserver.create_agent_local_socket(self.transport)
        sock = agent.local_socket.socket_path
        sid = Colors.stylize(self.sessionid, fg("light_blue") + attr("bold"))

        def _cmd(suffix: str) -> str:
            return Colors.stylize(
                f"SSH_AUTH_SOCK={sock} {suffix}", fg("light_blue") + attr("bold")
            )

        logging.info(
            "%s %s - agent socket ready - docs: https://docs.ssh-mitm.at/user_guide/sshagent.html",
            Colors.emoji("information"),
            sid,
        )
        logging.info(
            "%s %s - ssh-add:  %s", Colors.emoji("information"), sid, _cmd("ssh-add -l")
        )
        logging.info(
            "%s %s - ssh:      %s",
            Colors.emoji("information"),
            sid,
            _cmd("ssh user@host"),
        )

    def _start_channels(self) -> bool:
        self._request_agent()

        # create client or master channel
        if self.ssh.client:
            self.sftp.client_ready.set()
            self.netconf.client_ready.set()
            return True

        # Connect method start
        if not self.auth.agent:
            if self.auth.username_provided is None:
                logging.error("No username provided during login!")
                return False
            return (
                self.authenticator.auth_fallback(self.auth.username_provided)
                == paramiko.common.AUTH_SUCCESSFUL
            )

        if (
            self.authenticator.authenticate(store_credentials=False)
            != paramiko.common.AUTH_SUCCESSFUL
        ):
            if self.auth.username_provided is None:
                logging.error("No username provided during login!")
                return False
            if (
                self.authenticator.auth_fallback(self.auth.username_provided)
                == paramiko.common.AUTH_SUCCESSFUL
            ):
                return True
            self.transport.close()
            return False

        # Connect method end
        if (
            not self.scp.requested
            and not self.ssh.requested
            and not self.sftp.requested
            and not self.netconf.requested
        ) and self.transport.is_active():
            self.transport.close()
            return False

        self.sftp.client_ready.set()
        self.netconf.client_ready.set()
        return True

    def start(self) -> bool:
        """
        Start the session and initialize the underlying transport.
        """
        self.register_session_thread()
        event = threading.Event()
        self.transport.start_server(
            event=event, server=self.proxyserver.authentication_interface(self)
        )

        while not self.channel:
            self.channel = self.transport.accept(0.5)
            transport_error = self.transport.get_exception()
            if transport_error is not None and not isinstance(
                transport_error, EOFError
            ):
                self.transport.close()
                return False

        if not self.channel:
            logging.error("(%s) session error opening channel!", self)
            self.transport.close()
            return False

        # wait for authentication
        event.wait()

        if not self.transport.is_active():
            return False

        self.proxyserver.client_tunnel_interface.setup(self)

        if not self._start_channels():
            return False

        logging.info(
            "%s %s - session started",
            Colors.emoji("information"),
            Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
        )

        return True

    def close(self) -> None:
        """
        Close the session and release the underlying resources.
        """
        if self.auth.agent:
            self.auth.agent.close()
            logging.debug("(%s) session agent cleaned up", self)
        if self.ssh.client:
            logging.debug("(%s) closing ssh client to remote", self)
            if self.ssh.client.transport:
                self.ssh.client.transport.close()
            # With graceful exit the completion_event can be polled to wait, well ..., for completion
            # it can also only be a graceful exit if the ssh client has already been established
            if self.transport.completion_event is not None and (
                self.transport.completion_event.is_set() and self.transport.is_active()
            ):
                self.transport.completion_event.clear()
                while self.transport.is_active():
                    if self.transport.completion_event.wait(0.1):
                        break
        if self.transport.server_object is not None:
            for tunnel_forwarder in cast(
                "BaseServerInterface", self.transport.server_object
            ).forwarders:
                tunnel_forwarder.close()
                tunnel_forwarder.join()
        self.transport.close()
        self.authenticator.on_session_close()
        logging.info(
            "%s session %s closed",
            Colors.emoji("information"),
            Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
        )
        self.closed = True

    def __str__(self) -> str:
        return self.name

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type
        del exc_value
        del traceback
        logging.debug("(%s) session exited", self)
        self.close()
