import logging
import select
import threading
import socket

from ssh_proxy_server.forwarders.ssh import SSHForwarder


class SSHMirrorForwarder(SSHForwarder):

    @classmethod
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--ssh-injector-net',
            dest='ssh_injector_net',
            default='127.0.0.1',
            help='local address/interface where injector sessions are served'
        )

    def __init__(self, session):
        super().__init__(session)
        self.injector_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.injector_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.injector_sock.bind((self.args.ssh_injector_net, 0))
        self.injector_sock.listen(5)

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
                    logging.info("injector shell opened from %s", str(addr))
                    while True:
                        data = self.injector_client_sock.recv(self.BUF_LEN)
                        self.server_channel.sendall(data.strip(b'\n'))

        except Exception:
            logging.exception("injector connection suffered an unexpected error")
            self.close_session(self.channel)

    def close_session(self, channel):
        super().close_session(channel)
        logging.info("closing injector connection %s", self.injector_sock.getsockname())
        self.injector_sock.close()
        self.conn_thread.join()

    def stdout(self, text):
        if self.injector_client_sock:
            self.injector_client_sock.sendall(text)
        return text

    def stderr(self, text):
        if self.injector_client_sock:
            self.injector_client_sock.sendall(text)
        return text
