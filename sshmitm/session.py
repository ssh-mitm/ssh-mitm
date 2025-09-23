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
from multiprocessing import Condition
from types import TracebackType
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple, Type, Union, cast
from uuid import uuid4

import paramiko
from colored.colored import attr, fg  # type: ignore[import-untyped]
from paramiko import Transport
from paramiko.ssh_exception import ChannelException

from sshmitm.forwarders.agent import AgentProxy
from sshmitm.interfaces.server import ProxyNetconfServer, ProxySFTPServer
from sshmitm.logger import THREAD_DATA, Colors
from sshmitm.moduleparser import BaseModule
from sshmitm.plugins.session import key_negotiation

if TYPE_CHECKING:
    from paramiko.pkey import PKey

    import sshmitm
    from sshmitm.interfaces.server import BaseServerInterface
    from sshmitm.server import SSHProxyServer  # noqa: F401


class BaseSession(BaseModule):
    """
    The `BaseSession` class serves as a base for session management in the system.

    This class should be subclassed to provide custom session management functionality.
    """

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
        client_address: Union[Tuple[str, int], Tuple[str, int, int, int]],
        authenticator: Type["sshmitm.authentication.Authenticator"],
        remoteaddr: Union[Tuple[str, int], Tuple[str, int, int, int]],
        banner_name: Optional[str] = None,
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
        self._transport: Optional[paramiko.Transport] = None

        self.channel: Optional[paramiko.Channel] = None

        self.proxyserver: "sshmitm.server.SSHProxyServer" = proxyserver
        self.client_socket = client_socket
        self.client_address = client_address
        self.name = f"{client_address}->{remoteaddr}"
        self.closed = False

        self.agent_requested: threading.Event = threading.Event()

        self.ssh_requested: bool = False
        self.ssh_channel: Optional[paramiko.Channel] = None
        self.ssh_client: Optional[sshmitm.clients.ssh.SSHClient] = None
        self.ssh_client_auth_finished: bool = False
        self.ssh_client_created: Condition = Condition()
        self.ssh_pty_kwargs: Optional[Dict[str, Any]] = None
        self.ssh_remote_channel: Optional[paramiko.Channel] = None

        self.scp_requested: bool = False
        self.scp_channel: Optional[paramiko.Channel] = None
        self.scp_command: bytes = b""

        self.netconf_requested: bool = False
        self.netconf_channel: Optional[paramiko.Channel] = None
        self.netconf_client: Optional[sshmitm.clients.netconf.NetconfClient] = None
        self.netconf_client_ready = threading.Event()
        self.netconf_command: bytes = b""

        self.sftp_requested: bool = False
        self.sftp_channel: Optional[paramiko.Channel] = None
        self.sftp_client: Optional[sshmitm.clients.sftp.SFTPClient] = None
        self.sftp_client_ready = threading.Event()

        self.username: str = ""
        self.username_provided: Optional[str] = None
        self.password: Optional[str] = None
        self.password_provided: Optional[str] = None
        self.socket_remote_address = remoteaddr
        self.remote_address: Tuple[Optional[str], Optional[int]] = (None, None)
        self.remote_address_reachable: bool = True
        self.remote_key: Optional[PKey] = None
        self.accepted_key: Optional[PKey] = None
        self.agent: Optional[AgentProxy] = None
        self.authenticator: "sshmitm.authentication.Authenticator" = authenticator(self)

        self.env_requests: Dict[bytes, bytes] = {}
        self.session_log_dir: Optional[str] = self.get_session_log_dir()
        self.banner_name = banner_name

    def get_session_log_dir(self) -> Optional[str]:
        """
        Returns the directory where the ssh session logs will be stored.

        :return: The directory path where the ssh session logs will be stored, or `None` if the directory is not specified.
        """
        if not self.args.session_log_dir:
            return None
        session_log_dir = os.path.expanduser(self.args.session_log_dir)
        return os.path.join(session_log_dir, str(self.sessionid))

    @property
    def running(self) -> bool:
        """
        Returns the running state of the current session.

        :return: A boolean indicating whether the session is running or not
        """
        session_channel_open: bool = True
        ssh_channel_open: bool = False
        scp_channel_open: bool = False
        netconf_channel_open: bool = False

        if self.channel is not None:
            session_channel_open = not self.channel.closed
            if self.netconf_requested or self.netconf_channel is not None:
                logging.debug("DEBUG: Main session channel state - closed=%s, eof_received=%s, eof_sent=%s", 
                             self.channel.closed, self.channel.eof_received, self.channel.eof_sent)
        if self.ssh_channel is not None:
            ssh_channel_open = not self.ssh_channel.closed
        if self.scp_channel is not None:
            scp_channel_open = (
                not self.scp_channel.closed if self.scp_channel else False
            )
        if self.netconf_channel is not None:
            netconf_channel_open = (
                not self.netconf_channel.closed if self.netconf_channel else False
            )
            if self.netconf_requested or self.netconf_channel is not None:
                logging.debug("DEBUG: NETCONF channel state - closed=%s, eof_received=%s, eof_sent=%s", 
                             self.netconf_channel.closed, self.netconf_channel.eof_received, self.netconf_channel.eof_sent)
        open_channel_exists = (
            session_channel_open
            or ssh_channel_open
            or scp_channel_open
            or netconf_channel_open
        )

        is_running = self.proxyserver.running and open_channel_exists and not self.closed
        
        # Debug logging for NETCONF troubleshooting
        if self.netconf_requested or self.netconf_channel is not None:
            logging.debug("DEBUG: Session.running check - session_channel_open=%s, ssh_channel_open=%s, scp_channel_open=%s, netconf_channel_open=%s", 
                         session_channel_open, ssh_channel_open, scp_channel_open, netconf_channel_open)
            logging.debug("DEBUG: Session.running check - proxyserver.running=%s, open_channel_exists=%s, closed=%s, result=%s", 
                         self.proxyserver.running, open_channel_exists, self.closed, is_running)
        
        return is_running

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
            key_negotiation.handle_key_negotiation(self)
            if self.CIPHERS:
                if not isinstance(self.CIPHERS, tuple):
                    msg = "ciphers must be a tuple"
                    raise ValueError(msg)
                self._transport.get_security_options().ciphers = self.CIPHERS
            host_key: Optional[PKey] = self.proxyserver.host_key
            if host_key is not None:
                self._transport.add_server_key(host_key)
            # this will set the subsystemhandler to ProxySFTPServer and passes the arguments
            self._transport.set_subsystem_handler(
                name="sftp",
                handler=ProxySFTPServer,
                sftp_si=self.proxyserver.sftp_interface,
                session=self,
            )
            self._transport.set_subsystem_handler(
                "netconf", ProxyNetconfServer, self.proxyserver.netconf_interface, self
            )

        return self._transport

    def _request_agent(self) -> bool:
        requested_agent = None
        if self.agent is None or self.authenticator.REQUEST_AGENT_BREAKIN:
            try:
                if (
                    self.agent_requested.wait(1)
                    or self.authenticator.REQUEST_AGENT_BREAKIN
                ):
                    requested_agent = AgentProxy(self.transport)
                    logging.info(
                        "%s %s - successfully requested ssh-agent",
                        Colors.emoji("information"),
                        Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
                    )
            except ChannelException:
                logging.info(
                    "%s %s - ssh-agent breakin not successfull!",
                    Colors.emoji("warning"),
                    Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
                )
                return False
        self.agent = requested_agent or self.agent
        return self.agent is not None

    def _start_channels(self) -> bool:
        logging.debug("DEBUG: _start_channels() called")
        logging.debug("DEBUG: Session state - scp_requested=%s, ssh_requested=%s, sftp_requested=%s, netconf_requested=%s", 
                     self.scp_requested, self.ssh_requested, self.sftp_requested, self.netconf_requested)
        
        self._request_agent()
        logging.debug("DEBUG: After _request_agent(), agent=%s", self.agent)

        # create client or master channel
        if self.ssh_client:
            logging.debug("DEBUG: ssh_client exists, setting ready flags and returning True")
            self.sftp_client_ready.set()
            self.netconf_client_ready.set()
            return True

        # Connect method start
        if not self.agent:
            logging.debug("DEBUG: No agent available, checking username_provided=%s", self.username_provided)
            if self.username_provided is None:
                logging.error("No username provided during login!")
                return False
            auth_result = self.authenticator.auth_fallback(self.username_provided)
            logging.debug("DEBUG: auth_fallback result=%s", auth_result)
            return auth_result == paramiko.common.AUTH_SUCCESSFUL

        logging.debug("DEBUG: Agent available, attempting authentication")
        auth_result = self.authenticator.authenticate(store_credentials=False)
        logging.debug("DEBUG: authenticate result=%s", auth_result)
        
        if auth_result != paramiko.common.AUTH_SUCCESSFUL:
            logging.debug("DEBUG: Authentication failed, trying auth_fallback")
            if self.username_provided is None:
                logging.error("No username provided during login!")
                return False
            fallback_result = self.authenticator.auth_fallback(self.username_provided)
            logging.debug("DEBUG: auth_fallback result=%s", fallback_result)
            if fallback_result == paramiko.common.AUTH_SUCCESSFUL:
                return True
            logging.debug("DEBUG: All authentication failed, closing transport")
            self.transport.close()
            return False

        # Connect method end
        logging.debug("DEBUG: Authentication successful, checking channel requests")
        logging.debug("DEBUG: Channel request states - scp_requested=%s, ssh_requested=%s, sftp_requested=%s, netconf_requested=%s", 
                     self.scp_requested, self.ssh_requested, self.sftp_requested, self.netconf_requested)
        logging.debug("DEBUG: Transport active=%s", self.transport.is_active())
        
        if (
            not self.scp_requested
            and not self.ssh_requested
            and not self.sftp_requested
            and not self.netconf_requested
        ) and self.transport.is_active():
            logging.warning("DEBUG: No channel requests received, closing transport - this may be the issue!")
            self.transport.close()
            return False

        logging.debug("DEBUG: _start_channels() completing successfully")
        self.sftp_client_ready.set()
        self.netconf_client_ready.set()
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

        logging.debug("DEBUG: About to setup client tunnel interface")
        self.proxyserver.client_tunnel_interface.setup(self)
        logging.debug("DEBUG: Client tunnel interface setup complete")

        logging.debug("DEBUG: About to call _start_channels()")
        if not self._start_channels():
            logging.warning("DEBUG: _start_channels() returned False - session will not start!")
            return False

        logging.info(
            "%s %s - session started",
            Colors.emoji("information"),
            Colors.stylize(self.sessionid, fg("light_blue") + attr("bold")),
        )
        logging.debug("DEBUG: Session start completed successfully")
        return True

    def close(self) -> None:
        """
        Close the session and release the underlying resources.
        """
        if self.agent:
            self.agent.close()
            logging.debug("(%s) session agent cleaned up", self)
        if self.ssh_client:
            logging.debug("(%s) closing ssh client to remote", self)
            if self.ssh_client.transport:
                self.ssh_client.transport.close()
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

    def __enter__(self) -> "Session":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        del exc_type
        del exc_value
        del traceback
        logging.debug("(%s) session exited", self)
        self.close()
