import logging
import queue
import select
import threading
import socket
import time

from ssh_proxy_server.forwarders.ssh import SSHForwarder


class SSHInjectableForwarder(SSHForwarder):

    @classmethod
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--ssh-injector-net',
            dest='ssh_injector_net',
            default='127.0.0.1',
            help='local address/interface where injector sessions are served'
        )
        cls.PARSER.add_argument(
            '--ssh-injector-disable-mirror',
            dest='ssh_injector_disable_mirror',
            action="store_true",
            help='disables host session mirroring for the injector shell'
        )

    def __init__(self, session):
        super(SSHInjectableForwarder, self).__init__(session)
        self.injector_ip = self.args.ssh_injector_net
        self.injector_port = 0
        self.injector_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.injector_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.injector_sock.bind((self.injector_ip, self.injector_port))
        self.injector_sock.listen(5)
        self.injector_running = True

        self.mirror_enabled = not self.args.ssh_injector_disable_mirror
        self.queue = queue.Queue()
        self.sender = self.session.ssh_channel
        self.injector_shells = []
        InjectorShell.BUF_LEN = self.BUF_LEN
        thread = threading.Thread(target=self.injector_connect)
        thread.start()
        self.conn_thread = thread
        logging.info("creating ssh injector shell %s, connect with telnet", self.injector_sock.getsockname())

    def injector_connect(self):
        try:
            while self.injector_running:
                readable = select.select([self.injector_sock], [], [], 0.5)[0]
                if len(readable) == 1 and readable[0] is self.injector_sock:
                    client, addr = self.injector_sock.accept()
                    logging.info("injector shell opened from %s to ('%s', %d)", str(addr), self.injector_ip, self.injector_port)
                    injector_shell = InjectorShell(addr, client, self)
                    injector_shell.start()
                    self.injector_shells.append(injector_shell)
                time.sleep(0.1)
        except OSError as e:
            logging.warning("injector connection suffered an unexpected error")
            logging.exception(e)
            self.close_session(self.channel)

    def forward_stdin(self):
        # MTODO: maybe add host priority (priority queue); silent mode with client blocking input from injectors
        if self.session.ssh_channel.recv_ready():
            buf = self.session.ssh_channel.recv(self.BUF_LEN)
            self.queue.put((buf, self.session.ssh_channel))

    def forward_stdout(self):
        if self.server_channel.recv_ready():
            buf = self.server_channel.recv(self.BUF_LEN)
            self.sender.sendall(buf)
            if self.mirror_enabled and self.sender == self.session.ssh_channel:
                for shell in self.injector_shells:
                    if shell.client_sock is not self.sender:
                        shell.client_sock.sendall(buf)

    def forward_extra(self):
        if not self.server_channel.recv_ready() and not self.session.ssh_channel.recv_ready() and not self.queue.empty():
            msg, sender = self.queue.get()
            if msg == b'\r\n' and sender is not self.session.ssh_channel:
                msg = b'\r'
            self.server_channel.sendall(msg)
            self.sender = sender
            self.queue.task_done()

    def close_session(self, channel):
        self.injector_running = False
        super().close_session(channel)
        for shell in self.injector_shells:
            shell.join()
        self.conn_thread.join()
        logging.info("closing injector connection %s", self.injector_sock.getsockname())
        self.injector_sock.close()


class InjectorShell(threading.Thread):

    BUF_LEN = 1024

    def __init__(self, remote, client_sock, forwarder):
        super(InjectorShell, self).__init__()
        self.remote = remote
        self.forwarder = forwarder
        self.queue = self.forwarder.queue
        self.client_sock = client_sock

    def run(self) -> None:
        try:
            while self.forwarder.injector_running:
                readable = select.select([self.client_sock], [], [], 0.5)[0]
                if len(readable) == 1 and readable[0] is self.client_sock:
                    data = self.client_sock.recv(self.BUF_LEN)
                    if data.rstrip() == b'exit' or data == b'':
                        break
                    self.queue.put((data, self.client_sock))
                time.sleep(0.1)
        except OSError:
            logging.warning("injector shell %s with unexpected error", str(self.remote))
        finally:
            self.terminate()

    def terminate(self):
        if self.forwarder.injector_running:
            self.forwarder.injector_shells.remove(self)
        self.client_sock.close()
        logging.warning("injector shell %s was closed", str(self.remote))
