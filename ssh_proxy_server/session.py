import logging
import threading

from paramiko import Transport, AUTH_SUCCESSFUL
from paramiko.ssh_exception import ChannelException

from ssh_proxy_server.forwarders.agent import AgentProxy
from ssh_proxy_server.interfaces.server import ProxySFTPServer
from ssh_proxy_server.plugins.session import cve202014145


class Session:

    CIPHERS = None

    def __init__(self, proxyserver, client_socket, client_address, authenticator, remoteaddr):

        self._transport = None

        self.channel = None

        self.proxyserver = proxyserver
        self.client_socket = client_socket
        self.client_address = client_address
        self.name = "{fr}->{to}".format(fr=client_address, to=remoteaddr)

        self.agent_requested = threading.Event()

        self.ssh = False
        self.ssh_channel = None
        self.ssh_client = None
        self.ssh_pty_kwargs = None

        self.scp = False
        self.scp_channel = None
        self.scp_command = ''

        self.sftp = False
        self.sftp_channel = None
        self.sftp_client = None
        self.sftp_client_ready = threading.Event()

        self.username = ''
        self.socket_remote_address = remoteaddr
        self.remote_address = (None, None)
        self.key = None
        self.agent = None
        self.authenticator = authenticator(self)

    @property
    def running(self):
        # Using status of main channels to determine session status (-> releasability of resources)
        # - often calculated, cpu heavy (?)
        ch_active = all([not ch.closed for ch in filter(None, [self.ssh_channel, self.scp_channel, self.sftp_channel])])
        return self.proxyserver.running and ch_active

    @property
    def transport(self):
        if not self._transport:
            self._transport = Transport(self.client_socket)
            cve202014145.hookup_cve_2020_14145(self)
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

        if not self.agent and (self.authenticator.REQUEST_AGENT or self.authenticator.REQUEST_AGENT_BREAKIN):
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
            logging.error('no ssh agent forwarded')
            return False

        if self.authenticator.authenticate() != AUTH_SUCCESSFUL:
            logging.error('Permission denied (publickey)')
            return False

        # Connect method end
        if not self.scp and not self.ssh and not self.sftp:
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

        if not self._start_channels():
            return False

        logging.debug("(%s) session started", self)
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
        self.transport.close()
        logging.debug("(%s) session closed", self)

    def __str__(self):
        return self.name

    def __enter__(self):
        return self

    def __exit__(self, value_type, value, traceback):
        self.close()
