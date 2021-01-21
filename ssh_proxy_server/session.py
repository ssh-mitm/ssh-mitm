import logging
import threading

from paramiko import Transport, AUTH_SUCCESSFUL
from paramiko.agent import AgentServerProxy

from ssh_proxy_server.interfaces.server import ProxySFTPServer


class Session:
    CIPHERS = None

    def __init__(self, proxyserver, client_socket, client_address, authenticator, remoteaddr):

        self._transport = None

        self.channel = None

        self.proxyserver = proxyserver
        self.client_socket = client_socket
        self.client_address = client_address
        self.name = "{fr}->{to}".format(fr=client_address[0].split(":")[-1], to=remoteaddr[0].split(":")[-1])

        self.ssh = False
        self.ssh_channel = None
        self.ssh_client = None

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

        if not self.agent and self.authenticator.AGENT_FORWARDING:
            try:
                self.agent = AgentServerProxy(self.transport)
                self.agent.connect()
            except Exception:
                self.close()
                return False
        # Connect method start
        if not self.agent:
            self.channel.send('Kein SSH Agent weitergeleitet\r\n')
            return False

        if self.authenticator.authenticate() != AUTH_SUCCESSFUL:
            self.channel.send('Permission denied (publickey).\r\n')
            return False
        logging.info('connection established')

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
                if self.transport.is_active():
                    self.transport.close()
                return False

        if not self.channel:
            logging.error('(%s) session error opening channel!', self)
            if self.transport.is_active():
                self.transport.close()
            return False

        # wait for authentication
        event.wait()

        if not self.transport.is_active():
            return False

        if not self._start_channels():
            return False

        logging.info("(%s) session started", self)
        return True

    def close(self):
        if self.agent:
            logging.debug("(%s) session cleaning up agent ... (because paramiko IO bocks, in a new Thread)", self)
            self.agent._close()
            # INFO: Agent closing sequence takes 15 minutes, due to blocking IO in paramiko
            # Paramiko agent.py tries to connect to a UNIX_SOCKET; it should be created as well (prob) BUT never is
            # Agents starts Thread -> leads to the socket.connect blocking; only returns after .join(1000) timeout
            threading.Thread(target=self.agent.close).start()
            # Can throw FileNotFoundError due to no verification (agent.py)
            logging.debug("(%s) session agent cleaned up", self)
        if self.ssh_client:
            logging.info("(%s) closing ssh client to remote", self)
            self.ssh_client.transport.close()
            # With graceful exit the completion_event can be polled to wait, well ..., for completion
            # it can also only be a graceful exit if the ssh client has already been established
            if self.transport.completion_event.is_set() and self.transport.is_active():
                self.transport.completion_event.clear()
                self.transport.completion_event.wait()
        self.transport.close()
        logging.info("(%s) session closed", self)

    def __str__(self):
        return self.name

    def __enter__(self):
        return self

    def __exit__(self, value_type, value, traceback):
        self.close()
