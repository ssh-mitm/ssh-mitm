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
            '--ssh-injector-port',
            dest='ssh_injector_port',
            default=0,
            type=int,
            help='local port where injector sessions are served'
        )
        cls.PARSER.add_argument(
            '--ssh-injector-disable-mirror',
            dest='ssh_injector_disable_mirror',
            help='disables host session mirroring for the injector shell'
        )

    def __init__(self, session):
        super(SSHInjectableForwarder, self).__init__(session)
        self.injector_ip = self.args.ssh_injector_net
        self.injector_port = self.args.ssh_injector_port
        self.injector_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.injector_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        while True: # test/fix this
            b = self.injector_sock.connect_ex((self.injector_ip, self.injector_port)) == 0
            logging.debug(b)
            logging.debug(self.injector_port)
            if b:
                self.injector_port += 1
            else:
                self.injector_sock.bind((self.injector_ip, self.injector_port))
                break
        self.injector_sock.listen(5)

        self.mirror_enabled = False if self.args.ssh_injector_disable_mirror else True
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
            while self.session.running:
                readable = select.select([self.injector_sock], [], [])[0]
                if len(readable) == 1 and readable[0] is self.injector_sock:
                    client, addr = self.injector_sock.accept()
                    logging.info("injector shell opened from %s", str(addr))
                    injector_shell = InjectorShell(client, self.queue)
                    injector_shell.start()
                    self.injector_shells.append(injector_shell)
        except Exception as e:
            logging.warning("injector connection suffered an unexpected error")
            logging.exception(e)
            self.close_session(self.channel)

    def forward_stdin(self):    # maybe add host priority (priority queue)
        if self.session.ssh_channel.recv_ready():
            buf = self.session.ssh_channel.recv(self.BUF_LEN)
            self.queue.put((buf, self.session.ssh_channel))

    def forward_stdout(self):
        if self.server_channel.recv_ready():
            buf = self.server_channel.recv(self.BUF_LEN)
            self.sender.sendall(buf)
            if self.mirror_enabled:
                for shell in self.injector_shells:
                    if shell.client_sock is not self.sender:
                        shell.client_sock.sendall(buf)

    def forward_extra(self):
        if not self.server_channel.recv_ready() and not self.session.ssh_channel.recv_ready() and not self.queue.empty():
            msg, sender = self.queue.get()
            logging.debug("QUEUED MSG: " + str(msg))
            if msg == b'\r\n' and sender is not self.session.ssh_channel:
                msg = b'\r'
            self.server_channel.sendall(msg)
            self.sender = sender
            self.queue.task_done()

    def close_session(self, channel):
        super().close_session(channel)
        logging.info("closing injector connection %s", self.injector_sock.getsockname())
        self.injector_sock.close()
        self.conn_thread.join()
        for shell in self.injector_shells:
            shell.join()


class InjectorShell(threading.Thread):

    BUF_LEN = 1024

    def __init__(self, client_sock, queue):
        super(InjectorShell, self).__init__()
        self.queue = queue
        self.client_sock = client_sock

    def run(self) -> None:
        try:
            while True:
                data = self.client_sock.recv(self.BUF_LEN)
                if data == b'exit':
                    break
                self.queue.put((data, self.client_sock))
                time.sleep(0.1)
        except OSError:
            logging.warning("injector shell %s was closed unexpectedly", self.client_sock.getsockname())
        finally:
            self.join()

    def join(self, timeout=None) -> None:
        super(InjectorShell, self).join(timeout)
        self.client_sock.close()
