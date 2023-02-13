from binascii import hexlify
import logging
import os
import select
import time
import threading
import sys
from argparse import Namespace
from socket import socket

from typing import (
    Optional,
    Type,
    Tuple,
    List,
    Union
)

from colored import stylize, attr, fg  # type: ignore

from paramiko import DSSKey, RSAKey, ECDSAKey, Ed25519Key, PKey
from paramiko.ssh_exception import SSHException
from sshpubkeys import SSHKey  # type: ignore

from sshmitm.console import sshconsole
from sshmitm.multisocket import (
    create_server_sock,
    has_dual_stack,
    MultipleSocketsListener
)
from sshmitm.session import Session
from sshmitm.forwarders.ssh import SSHBaseForwarder, SSHForwarder
from sshmitm.forwarders.scp import SCPBaseForwarder, SCPForwarder
from sshmitm.forwarders.sftp import SFTPHandlerBasePlugin, SFTPHandlerPlugin
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface
from sshmitm.forwarders.tunnel import LocalPortForwardingForwarder, RemotePortForwardingForwarder
from sshmitm.authentication import Authenticator, AuthenticatorPassThrough
from sshmitm.interfaces.server import BaseServerInterface, ServerInterface
from sshmitm.exceptions import KeyGenerationError


class SSHProxyServer:
    SELECT_TIMEOUT = 0.5

    def __init__(
        self,
        listen_port: int,
        *,
        key_file: Optional[str] = None,
        key_algorithm: str = 'rsa',
        key_length: int = 2048,
        ssh_interface: Type[SSHBaseForwarder] = SSHForwarder,
        scp_interface: Type[SCPBaseForwarder] = SCPForwarder,
        sftp_interface: Type[BaseSFTPServerInterface] = SFTPProxyServerInterface,
        sftp_handler: Type[SFTPHandlerBasePlugin] = SFTPHandlerPlugin,
        server_tunnel_interface: Type[RemotePortForwardingForwarder] = RemotePortForwardingForwarder,
        client_tunnel_interface: Type[LocalPortForwardingForwarder] = LocalPortForwardingForwarder,
        authentication_interface: Type[BaseServerInterface] = ServerInterface,
        authenticator: Type[Authenticator] = AuthenticatorPassThrough,
        transparent: bool = False,
        session_class: Type[Session] = Session,
        args: Optional[Namespace] = None
    ) -> None:
        self.args = args

        self._threads: List[threading.Thread] = []
        self._hostkey: Optional[PKey] = None

        self.listen_port = listen_port
        self.listen_address = '0.0.0.0'  # nosec
        self.listen_address_v6 = '::'
        self.running = False

        self.key_file: Optional[str] = key_file
        self.key_algorithm: str = key_algorithm
        self.key_length: int = key_length

        self.ssh_interface: Type[SSHBaseForwarder] = ssh_interface
        self.scp_interface: Type[SCPBaseForwarder] = scp_interface
        self.sftp_handler: Type[SFTPHandlerBasePlugin] = sftp_handler
        self.sftp_interface: Type[BaseSFTPServerInterface] = self.sftp_handler.get_interface() or sftp_interface
        self.server_tunnel_interface: Type[RemotePortForwardingForwarder] = server_tunnel_interface
        self.client_tunnel_interface: Type[LocalPortForwardingForwarder] = client_tunnel_interface
        # Server Interface
        self.authentication_interface: Type[BaseServerInterface] = authentication_interface
        self.authenticator: Type[Authenticator] = authenticator
        self.transparent: bool = transparent
        self.session_class: Type[Session] = session_class

        try:
            self.generate_host_key()
        except KeyGenerationError:
            sys.exit(1)

    def generate_host_key(self) -> None:
        key_algorithm_class: Optional[Type[PKey]] = None
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
                self._hostkey = key_algorithm_class.generate(bits=key_algorithm_bits)  # type: ignore
            except ValueError as err:
                logging.error(str(err))
                raise KeyGenerationError() from err
        else:
            if not os.path.isfile(self.key_file):
                raise FileNotFoundError(f"host key '{self.key_file}' file does not exist")
            for pkey_class in (RSAKey, DSSKey, ECDSAKey, Ed25519Key):
                try:
                    key = self._key_from_filepath(
                        self.key_file, pkey_class, None
                    )
                    self._hostkey = key
                    break
                except SSHException:
                    pass
            else:
                logging.error('host key format not supported!')
                raise KeyGenerationError()

        ssh_pub_key = SSHKey(f"{self._hostkey.get_name()} {self._hostkey.get_base64()}")
        ssh_pub_key.parse()
        print(
            (
                "{} {} key "  # pylint: disable=consider-using-f-string
                "with {} bit length and fingerprints:\n"
                "   {}\n"
                "   {}\n"
                "   {}"
            ).format(
                'loaded' if self.key_file else 'generated temporary',
                key_algorithm_class.__name__,
                self._hostkey.get_bits(),
                stylize(ssh_pub_key.hash_md5(), fg('light_blue') + attr('bold')),
                stylize(ssh_pub_key.hash_sha256(), fg('light_blue') + attr('bold')),
                stylize(ssh_pub_key.hash_sha512(), fg('light_blue') + attr('bold'))
            )
        )

    def _key_from_filepath(self, filename: str, klass: Type[PKey], password: Optional[str]) -> PKey:
        """
        Attempt to derive a `.PKey` from given string path ``filename``:
        - If ``filename`` appears to be a cert, the matching private key is
          loaded.
        - Otherwise, the filename is assumed to be a private key, and the
          matching public cert will be loaded if it exists.
        """
        cert_suffix = "-cert.pub"
        # Assume privkey, not cert, by default
        if filename.endswith(cert_suffix):
            key_path = filename[: -len(cert_suffix)]
            cert_path = filename
        else:
            key_path = filename
            cert_path = filename + cert_suffix
        # Blindly try the key path; if no private key, nothing will work.
        key = klass.from_private_key_file(key_path, password)
        # TODO: change this to 'Loading' instead of 'Trying' sometime; probably
        # when #387 is released, since this is a critical log message users are
        # likely testing/filtering for (bah.)
        hexlify(key.get_fingerprint())
        # Attempt to load cert if it exists.
        if os.path.isfile(cert_path):
            key.load_certificate(cert_path)
        return key

    @property
    def host_key(self) -> Optional[PKey]:
        if not self._hostkey:
            self.generate_host_key()
        return self._hostkey

    @staticmethod
    def _clean_environment() -> None:
        for env_var in [
            'SSH_ASKPASS',
            'SSH_AUTH_SOCK',
            'SSH_CLIENT',
            'SSH_CONNECTION',
            'SSH_ORIGINAL_COMMAND',
            'SSH_TTY'
        ]:
            try:
                del os.environ[env_var]
                logging.debug("removed %s from environment", env_var)
            except KeyError:
                pass

    def start(self) -> None:
        self._clean_environment()
        sock: Optional[Union[socket, MultipleSocketsListener]] = None

        try:
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
        except PermissionError as permerror:
            if self.transparent and permerror.errno == 1:
                logging.error(
                    "%s Note: running SSH-MITM in transparent mode requires root privileges",
                    stylize('error creating socket!', fg('red') + attr('bold'))
                )
            elif permerror.errno == 13 and self.listen_port < 1024:
                logging.error(
                    "%s Note: running SSH-MITM on a port < 1024 requires root privileges",
                    stylize('error creating socket!', fg('red') + attr('bold'))
                )
            else:
                logging.exception(
                    "%s - unknown error",
                    stylize('error creating socket!', fg('red') + attr('bold'))
                )
            return
        if sock is None:
            logging.error(
                "%s",
                stylize('error creating socket!', fg('red') + attr('bold'))
            )
            return

        print(
            'listen interfaces {} and {} on port {}'.format(  # pylint: disable=consider-using-f-string
                self.listen_address,
                self.listen_address_v6,
                self.listen_port
            )
        )
        if self.transparent:
            print(f"{stylize('Transparent mode enabled!', attr('bold'))} (experimental)")
        sshconsole.rule("[red]waiting for connections", style="red")

        self.running = True
        try:
            while self.running:
                readable = select.select([sock], [], [], self.SELECT_TIMEOUT)[0]
                if len(readable) == 1 and readable[0] is sock:
                    client, addr = sock.accept()
                    remoteaddr = client.getsockname()
                    logging.debug('incoming connection from %s to %s', str(addr), remoteaddr)

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

    def create_session(
        self,
        client: socket,
        addr: Union[Tuple[str, int], Tuple[str, int, int, int]],
        remoteaddr: Union[Tuple[str, int], Tuple[str, int, int, int]]
    ) -> None:
        try:
            with self.session_class(self, client, addr, self.authenticator, remoteaddr) as session:
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
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("error handling session creation")
