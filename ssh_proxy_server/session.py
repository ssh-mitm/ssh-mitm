import logging
import threading
from uuid import uuid4
import os

from enhancements.modules import BaseModule

from colored.colored import stylize, fg, attr
from rich._emoji_codes import EMOJI

from paramiko import Transport, AUTH_SUCCESSFUL
from paramiko.ssh_exception import ChannelException

from ssh_proxy_server.forwarders.agent import AgentProxy
from ssh_proxy_server.interfaces.server import ProxySFTPServer
from ssh_proxy_server.plugins.session import key_negotiation
from ssh_proxy_server.plugins.tunnel.injectclienttunnel import InjectableClientTunnelForwarder


class BaseSession(BaseModule):
    pass


class Session(BaseSession):

    CIPHERS = None

    @classmethod
    def parser_arguments(cls):
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--session-log-dir',
            dest='session_log_dir',
            help='directory to store ssh session logs'
        )

    def __init__(self, proxyserver, client_socket, client_address, authenticator, remoteaddr):
        super().__init__()
        self.sessionid = uuid4()
        logging.info(f"{EMOJI['information']} session {stylize(self.sessionid, fg('light_blue') + attr('bold'))} created")
        self._transport = None

        self.channel = None

        self.proxyserver = proxyserver
        self.client_socket = client_socket
        self.client_address = client_address
        self.name = f"{client_address}->{remoteaddr}"
        self.closed = False

        self.agent_requested = threading.Event()

        self.ssh_requested = False
        self.ssh_channel = None
        self.ssh_client = None
        self.ssh_pty_kwargs = None

        self.scp_requested = False
        self.scp_channel = None
        self.scp_command = ''

        self.sftp_requested = False
        self.sftp_channel = None
        self.sftp_client = None
        self.sftp_client_ready = threading.Event()

        self.username = ''
        self.username_provided = None
        self.password = None
        self.password_provided = None
        self.socket_remote_address = remoteaddr
        self.remote_address = (None, None)
        self.key = None
        self.agent = None
        self.authenticator = authenticator(self)

        self.env_requests = {}
        self.session_log_dir = self.get_session_log_dir()

    def get_session_log_dir(self):
        if not self.args.session_log_dir:
            return None
        session_log_dir = os.path.expanduser(self.args.session_log_dir)
        return os.path.join(
            session_log_dir,
            str(self.sessionid)
        )

    @property
    def running(self):
        session_channel_open = not self.channel.closed if self.channel else True
        ssh_channel_open = not self.ssh_channel.closed if self.ssh_channel else False
        scp_channel_open = not self.scp_channel.closed if self.scp_channel else False
        open_channel_exists = session_channel_open or ssh_channel_open or scp_channel_open

        return_value = self.proxyserver.running and open_channel_exists and not self.closed
        return return_value

    @property
    def transport(self):
        if not self._transport:
            self._transport = Transport(self.client_socket)
            key_negotiation.handle_key_negotiation(self)
            if self.CIPHERS:
                if not isinstance(self.CIPHERS, tuple):
                    raise ValueError('ciphers must be a tuple')
                self._transport.get_security_options().ciphers = self.CIPHERS
            self._transport.add_server_key(self.proxyserver.host_key)
            self._transport.set_subsystem_handler('sftp', ProxySFTPServer, self.proxyserver.sftp_interface)

        return self._transport

    def _start_channels(self):
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
            return self.authenticator.auth_fallback(self.username_provided) == AUTH_SUCCESSFUL

        if self.authenticator.authenticate(store_credentials=False) != AUTH_SUCCESSFUL:
            logging.error('Permission denied (publickey)')
            return False

        # Connect method end
        if not self.scp_requested and not self.ssh_requested and not self.sftp_requested:
            if self.transport.is_active():
                self.transport.close()
                return False

        self.sftp_client_ready.set()
        return True

    def start(self):
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

        # Setup the InjectableClientTunnelForwarder (after master channel init)
        if self.proxyserver.client_tunnel_interface is InjectableClientTunnelForwarder:
            self.proxyserver.client_tunnel_interface.setup_injector(self)

        if not self._start_channels():
            return False

        logging.info(f"{EMOJI['information']} session started: {stylize(self.sessionid, fg('light_blue') + attr('bold'))}")
        return True

    def close(self):
        if self.agent:
            self.agent.close()
            logging.debug("(%s) session agent cleaned up", self)
        if self.ssh_client:
            logging.debug("(%s) closing ssh client to remote", self)
            self.ssh_client.transport.close()
            # With graceful exit the completion_event can be polled to wait, well ..., for completion
            # it can also only be a graceful exit if the ssh client has already been established
            if self.transport.completion_event.is_set() and self.transport.is_active():
                self.transport.completion_event.clear()
                while self.transport.is_active():
                    if self.transport.completion_event.wait(0.1):
                        break
        for f in self.transport.server_object.forwarders:
            f.close()
            f.join()
        self.transport.close()
        logging.info(f"{EMOJI['information']} session {stylize(self.sessionid, fg('light_blue') + attr('bold'))} closed")
        logging.debug(f"({self}) session closed")
        self.closed = True

    def __str__(self):
        return self.name

    def __enter__(self):
        return self

    def __exit__(self, value_type, value, traceback):
        logging.debug("(%s) session exited", self)
        self.close()
