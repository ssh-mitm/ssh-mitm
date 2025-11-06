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

from sshmitm.core.forwarders.base import BaseForwarder
from sshmitm.core.interfaces.server import ProxySFTPServer
from sshmitm.core.logger import THREAD_DATA, Colors
from sshmitm.moduleparser import BaseModule
from sshmitm.plugins.session import key_negotiation

if TYPE_CHECKING:
    from paramiko.pkey import PKey

    import sshmitm
    from sshmitm.core.interfaces.server import BaseServerInterface
    from sshmitm.core.server import SSHProxyServer  # noqa: F401


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

    :param proxyserver: Instance of 'sshmitm.core.server.SSHProxyServer' class
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
        proxyserver: "sshmitm.core.server.SSHProxyServer",
        client_socket: socket.socket,
        client_address: Union[Tuple[str, int], Tuple[str, int, int, int]],
        authenticator: Type["sshmitm.core.authentication.Authenticator"],
        remoteaddr: Union[Tuple[str, int], Tuple[str, int, int, int]],
        banner_name: Optional[str] = None,
    ) -> None:
        """
        Initialize the class instance.

        :param proxyserver: Instance of 'sshmitm.core.server.SSHProxyServer' class
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

        self.proxyserver: "sshmitm.core.server.SSHProxyServer" = proxyserver
        self.client_socket = client_socket
        self.client_address = client_address
        self.name = f"{client_address}->{remoteaddr}"
        self.closed = False

        self._registered_interfaces = {}

        self.ssh_client: Optional[sshmitm.core.clients.ssh.SSHClient] = None
        self.ssh_client_auth_finished: bool = False
        self.ssh_client_created: Condition = Condition()
        self.ssh_pty_kwargs: Optional[Dict[str, Any]] = None

        self.sftp_requested: bool = False
        self.sftp_channel: Optional[paramiko.Channel] = None
        self.sftp_client: Optional[sshmitm.core.clients.sftp.SFTPClient] = None
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
        self.authenticator: "sshmitm.core.authentication.Authenticator" = authenticator(
            self
        )

        self.env_requests: Dict[bytes, bytes] = {}
        self.session_log_dir: Optional[str] = self.get_session_log_dir()
        self.banner_name = banner_name

    def register_interface(
        self,
        *,
        name: str,
        interface: Type[BaseForwarder],
        client_channel: paramiko.Channel,
        **kwargs: object,
    ) -> bool:
        if name in self._registered_interfaces:
            return False
        self._registered_interfaces[name] = interface(
            self, client_channel=client_channel, **kwargs
        )
        return True

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

        if self.channel is not None:
            session_channel_open = not self.channel.closed
        if "ssh" in self._registered_interfaces:
            ssh_channel_open = self._registered_interfaces["ssh"].is_active
        if "scp" in self._registered_interfaces:
            scp_channel_open = self._registered_interfaces["scp"].is_active
        open_channel_exists = (
            session_channel_open or ssh_channel_open or scp_channel_open
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

        return self._transport

    def _start_channels(self) -> bool:
        self.authenticator.request_agent()

        # create client or master channel
        if self.ssh_client:
            self.sftp_client_ready.set()
            return True

        # Connect method start
        if not self.authenticator.has_forwarded_agent:
            if self.username_provided is None:
                logging.error("No username provided during login!")
                return False
            return (
                self.authenticator.auth_fallback(self.username_provided)
                == paramiko.common.AUTH_SUCCESSFUL
            )

        if (
            self.authenticator.authenticate(store_credentials=False)
            != paramiko.common.AUTH_SUCCESSFUL
        ):
            if self.username_provided is None:
                logging.error("No username provided during login!")
                return False
            if (
                self.authenticator.auth_fallback(self.username_provided)
                == paramiko.common.AUTH_SUCCESSFUL
            ):
                return True
            self.transport.close()
            return False

        # Connect method end
        if (
            "scp" not in self._registered_interfaces
            and "ssh" not in self._registered_interfaces
            and not self.sftp_requested
        ) and self.transport.is_active():
            self.transport.close()
            return False

        self.sftp_client_ready.set()
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
        self.authenticator.close()
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
