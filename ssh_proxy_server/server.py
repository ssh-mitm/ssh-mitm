import logging
import os
import select
import time
import threading
import sys

from colored import stylize, attr, fg

from paramiko import DSSKey, RSAKey, ECDSAKey, Ed25519Key
from sshpubkeys import SSHKey

from ssh_proxy_server.multisocket import (
    create_server_sock,
    has_dual_stack,
    MultipleSocketsListener
)
from ssh_proxy_server.session import Session
from ssh_proxy_server.exceptions import KeyGenerationError


class SSHProxyServer:
    SELECT_TIMEOUT = 0.5

    def __init__(
        self,
        listen_port,
        key_file=None,
        key_algorithm='rsa',
        key_length=2048,
        ssh_interface=None,
        scp_interface=None,
        sftp_interface=None,
        sftp_handler=None,
        server_tunnel_interface=None,
        client_tunnel_interface=None,
        authentication_interface=None,
        authenticator=None,
        transparent=False,
        args=None
    ):
        self.args = args

        self._threads = []
        self._hostkey = None

        self.listen_port = listen_port
        self.listen_address = '0.0.0.0'  # nosec
        self.listen_address_v6 = '::'
        self.running = False

        self.key_file = key_file
        self.key_algorithm = key_algorithm
        self.key_length = key_length

        self.ssh_interface = ssh_interface
        self.scp_interface = scp_interface
        self.sftp_handler = sftp_handler
        self.sftp_interface = self.sftp_handler.get_interface() or sftp_interface
        self.server_tunnel_interface = server_tunnel_interface
        self.client_tunnel_interface = client_tunnel_interface
        # Server Interface
        self.authentication_interface = authentication_interface
        self.authenticator = authenticator
        self.transparent = transparent

        try:
            self.generate_host_key()
        except KeyGenerationError:
            sys.exit(1)

    def generate_host_key(self):
        key_algorithm_class = None
        key_algorithm_bits = None
        if self.key_algorithm == 'dss':
            key_algorithm_class = DSSKey
            key_algorithm_bits = self.key_length
        elif self.key_algorithm == 'rsa':
            key_algorithm_class = RSAKey
            key_algorithm_bits = self.key_length
        elif self.key_algorithm == 'ecdsa':
            key_algorithm_class = ECDSAKey
        elif self.key_algorithm == 'ed25519':
            key_algorithm_class = Ed25519Key
            if not self.key_file:
                logging.error("ed25519 requires a key file, please use also use --host-key parameter")
                sys.exit(1)
        else:
            raise ValueError(f"host key algorithm '{self.key_algorithm}' not supported!")

        if not self.key_file:
            try:
                self._hostkey = key_algorithm_class.generate(bits=key_algorithm_bits)
            except ValueError as err:
                logging.error(str(err))
                raise KeyGenerationError()
        else:
            if not os.path.isfile(self.key_file):
                raise FileNotFoundError(f"host key '{self.key_file}' file does not exist")
            try:
                self._hostkey = key_algorithm_class(filename=self.key_file)
            except Exception:
                logging.error('host key format not supported by selected algorithm "%s"!', self.key_algorithm)
                raise KeyGenerationError()


        ssh_pub_key = SSHKey(f"{self._hostkey.get_name()} {self._hostkey.get_base64()}")
        ssh_pub_key.parse()
        logging.info((
            f"{'loaded' if self.key_file else 'generated temporary'} {key_algorithm_class.__name__} key with {self._hostkey.get_bits()} bit length and fingerprints:\n"
            f"    {stylize(ssh_pub_key.hash_md5(), fg('light_blue') + attr('bold'))}\n"
            f"    {stylize(ssh_pub_key.hash_sha256(),fg('light_blue') + attr('bold'))}"
        ))

    @property
    def host_key(self):
        if not self._hostkey:
            self.generate_host_key()
        return self._hostkey

    def start(self):
        sock = create_server_sock(
            (self.listen_address, self.listen_port),
            transparent=self.transparent
        )
        if not has_dual_stack(sock):
            sock.close()
            sock = MultipleSocketsListener(
                [
                    (self.listen_address, self.listen_port),
                    (self.listen_address_v6, self.listen_port)
                ],
                transparent=self.transparent
            )

        logging.info(f'listen interfaces {self.listen_address} and {self.listen_address_v6} on port {self.listen_port}')
        self.running = True
        try:
            while self.running:
                readable = select.select([sock], [], [], self.SELECT_TIMEOUT)[0]
                if len(readable) == 1 and readable[0] is sock:
                    client, addr = sock.accept()
                    remoteaddr = client.getsockname()
                    logging.info(f'incoming connection from {str(addr)} to {remoteaddr}')

                    thread = threading.Thread(target=self.create_session, args=(client, addr, remoteaddr))
                    thread.start()
                    self._threads.append(thread)
        except KeyboardInterrupt:
            sys.stdout.write('\b\b\r')
            sys.stdout.flush()
            self.running = False
        finally:
            logging.info("[red]:exclamation: Shutting down server ...", extra={"markup": True})
            sock.close()
            for thread in self._threads[:]:
                thread.join()

    def create_session(self, client, addr, remoteaddr):
        try:
            with Session(self, client, addr, self.authenticator, remoteaddr) as session:
                if session.start():
                    while session.running:
                        time.sleep(0.1)
                        if session.ssh_requested and self.ssh_interface:
                            session.ssh_requested = False
                            self.ssh_interface(session).forward()
                        elif session.scp_requested and self.scp_interface:
                            session.scp_requested = False
                            scp_interface = self.scp_interface(session)
                            thread = threading.Thread(target=scp_interface.forward)
                            thread.start()

                else:
                    logging.warning("(%s) session not started", session)
                    self._threads.remove(threading.current_thread())
        except Exception:
            logging.exception("error handling session creation")
