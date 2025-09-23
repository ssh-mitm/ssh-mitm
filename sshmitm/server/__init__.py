import logging
import os
import select
import sys
import threading
import time
from binascii import hexlify
from socket import socket
from typing import List, Optional, Tuple, Type, Union

from colored import attr, fg  # type: ignore[import-untyped]
from paramiko import ECDSAKey, Ed25519Key, PKey, RSAKey
from paramiko.ssh_exception import SSHException
from rich import print as rich_print

from sshmitm import __version__ as ssh_mitm_version
from sshmitm.authentication import Authenticator, AuthenticatorPassThrough
from sshmitm.console import sshconsole
from sshmitm.exceptions import KeyGenerationError
from sshmitm.forwarders.netconf import NetconfBaseForwarder, NetconfForwarder
from sshmitm.forwarders.scp import SCPBaseForwarder, SCPForwarder
from sshmitm.forwarders.sftp import SFTPHandlerBasePlugin, SFTPHandlerPlugin
from sshmitm.forwarders.ssh import SSHBaseForwarder, SSHForwarder
from sshmitm.forwarders.tunnel import (
    LocalPortForwardingForwarder,
    RemotePortForwardingForwarder,
)
from sshmitm.interfaces.server import BaseServerInterface, ServerInterface
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface
from sshmitm.logger import Colors
from sshmitm.multisocket import create_server_sock
from sshmitm.session import Session
from sshmitm.utils import SSHPubKey


class SSHProxyServer:
    SELECT_TIMEOUT = 0.5

    def __init__(  # pylint: disable=too-many-arguments
        self,
        listen_address: str,
        listen_port: int,
        *,
        key_file: Optional[str] = None,
        key_algorithm: str = "rsa",
        key_length: int = 2048,
        ssh_interface: Type[SSHBaseForwarder] = SSHForwarder,
        scp_interface: Type[SCPBaseForwarder] = SCPForwarder,
        netconf_interface: Type[NetconfBaseForwarder] = NetconfForwarder,
        sftp_interface: Type[BaseSFTPServerInterface] = SFTPProxyServerInterface,
        sftp_handler: Type[SFTPHandlerBasePlugin] = SFTPHandlerPlugin,
        server_tunnel_interface: Type[
            RemotePortForwardingForwarder
        ] = RemotePortForwardingForwarder,
        client_tunnel_interface: Type[
            LocalPortForwardingForwarder
        ] = LocalPortForwardingForwarder,
        authentication_interface: Type[BaseServerInterface] = ServerInterface,
        authenticator: Type[Authenticator] = AuthenticatorPassThrough,
        transparent: bool = False,
        session_class: Type[Session] = Session,
        banner_name: Optional[str] = None,
        debug: bool = False,
    ) -> None:
        self._threads: List[threading.Thread] = []
        self._hostkey: Optional[PKey] = None

        self.listen_port = listen_port
        self.listen_address = listen_address
        self.running = False

        self.key_file: Optional[str] = key_file
        self.key_algorithm: str = key_algorithm
        self.key_algorithm_class: Optional[Type[PKey]] = None
        self.key_length: int = key_length

        self.ssh_interface: Type[SSHBaseForwarder] = ssh_interface
        self.scp_interface: Type[SCPBaseForwarder] = scp_interface
        self.netconf_interface: Type[NetconfBaseForwarder] = netconf_interface
        self.sftp_handler: Type[SFTPHandlerBasePlugin] = sftp_handler
        self.sftp_interface: Type[BaseSFTPServerInterface] = (
            self.sftp_handler.get_interface() or sftp_interface
        )
        self.server_tunnel_interface: Type[RemotePortForwardingForwarder] = (
            server_tunnel_interface
        )
        self.client_tunnel_interface: Type[LocalPortForwardingForwarder] = (
            client_tunnel_interface
        )
        # Server Interface
        self.authentication_interface: Type[BaseServerInterface] = (
            authentication_interface
        )
        self.authenticator: Type[Authenticator] = authenticator
        self.transparent: bool = transparent
        self.session_class: Type[Session] = session_class
        self.banner_name: Optional[str] = banner_name
        self.debug: bool = debug

        try:
            self.generate_host_key()
        except KeyGenerationError:
            sys.exit(1)

    def print_serverinfo(self, json_log: bool = False) -> None:
        if self.key_algorithm_class is None or self._hostkey is None:
            return
        ssh_host_key_pub = SSHPubKey(self._hostkey)
        log_data = {
            "keygeneration": "loaded" if self.key_file else "generated temporary",
            "algorithm": self.key_algorithm_class.__name__,
            "bits": self._hostkey.get_bits(),
            "md5": Colors.stylize(
                ssh_host_key_pub.hash_md5(), fg("light_blue") + attr("bold")
            ),
            "sha256": Colors.stylize(
                ssh_host_key_pub.hash_sha256(), fg("light_blue") + attr("bold")
            ),
            "sha512": Colors.stylize(
                ssh_host_key_pub.hash_sha512(), fg("light_blue") + attr("bold")
            ),
            "listen_address": self.listen_address,
            "listen_port": self.listen_port,
            "transparen_mode": self.transparent,
        }

        if json_log or not sys.stdout.isatty():
            logging.info("ssh-mitm server info", extra={"serverinfo": log_data})
        else:
            print("\33]0;SSH-MITM - ssh audits made simple\a", end="", flush=True)
            sshconsole.rule(
                "[bold blue]SSH-MITM - ssh audits made simple", style="blue"
            )
            if self.debug:
                rich_print(f"[bold]Version:[/bold] {ssh_mitm_version}")
                rich_print("[bold]License:[/bold] GNU General Public License v3.0")

            rich_print("[bold]Documentation:[/bold] https://docs.ssh-mitm.at")
            rich_print(
                "[bold]Issues:[/bold] https://github.com/ssh-mitm/ssh-mitm/issues"
            )
            sshconsole.rule("[blue]Configuration", style="blue")

            if os.environ.get("container"):  # noqa: SIM112
                rich_print(
                    "[bold red]:exclamation: You are executing SSH-MITM as Flatpak"
                )
                rich_print(
                    "Without further configuration, SSH-MITM can only access Flatpaks default data directory"
                )
                app_data = os.path.expanduser("~/.var/app/at.ssh_mitm.server/data/")
                folder_link = f"[link=file://{app_data}]{app_data}[/link]"
                rich_print(f"[bold]Data directory:[/bold] {folder_link}")
                rich_print(
                    ":light_bulb: If you need access to other files and directories, you can use [link=https://flathub.org/apps/com.github.tchx84.Flatseal]Flatseal[/link] to reconfigure SSH-MITM."
                )
                sshconsole.rule(characters=".", style="bright_black")

            rich_print("[bold blue]:key: SSH-Host-Keys:")
            print(
                (
                    "   {keygeneration} {algorithm} key with {bits} bit length\n"  # pylint: disable=consider-using-f-string
                    "   {md5}\n"
                    "   {sha256}\n"
                    "   {sha512}"
                ).format(**log_data)
            )
            sshconsole.rule(characters=".", style="bright_black")
            print(
                "{servericon} listen interfaces {listen_address} on port {listen_port}".format(
                    **log_data, servericon=Colors.emoji("computer")
                )
            )
            if self.transparent:
                rich_print(
                    ":exclamation: Transparent mode enabled [red bold](experimental)"
                )
            if self.debug:
                rich_print("[bold red]:exclamation: Debug mode enabled")
            sshconsole.rule("[red]waiting for connections", style="red")

    def generate_host_key(self) -> None:
        self.key_algorithm_class = None
        key_algorithm_bits = None
        if self.key_algorithm == "rsa":
            self.key_algorithm_class = RSAKey
            key_algorithm_bits = self.key_length
        elif self.key_algorithm == "ecdsa":
            self.key_algorithm_class = ECDSAKey
        elif self.key_algorithm == "ed25519":
            self.key_algorithm_class = Ed25519Key
            if not self.key_file:
                logging.error(
                    "ed25519 requires a key file, please use also use --host-key parameter"
                )
                sys.exit(1)
        else:
            msg = f"host key algorithm '{self.key_algorithm}' not supported!"
            raise ValueError(msg)

        if not self.key_file:
            try:
                self._hostkey = self.key_algorithm_class.generate(  # type: ignore[attr-defined]
                    bits=key_algorithm_bits
                )
            except ValueError as err:
                logging.error(str(err))
                raise KeyGenerationError from err
        else:
            if not os.path.isfile(self.key_file):
                msg = f"host key '{self.key_file}' file does not exist"
                raise FileNotFoundError(msg)
            for pkey_class in (RSAKey, ECDSAKey, Ed25519Key):
                try:
                    key = self._key_from_filepath(self.key_file, pkey_class, None)
                    self._hostkey = key
                    break
                except SSHException:
                    pass
            else:
                logging.error("host key format not supported!")
                raise KeyGenerationError

    def _key_from_filepath(
        self, filename: str, klass: Type[PKey], password: Optional[str]
    ) -> PKey:
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
            "SSH_ASKPASS",
            "SSH_AUTH_SOCK",
            "SSH_CLIENT",
            "SSH_CONNECTION",
            "SSH_ORIGINAL_COMMAND",
            "SSH_TTY",
        ]:
            if env_var in os.environ:
                del os.environ[env_var]
                logging.debug("removed %s from environment", env_var)

    def start(self) -> None:
        self._clean_environment()
        sock: Optional[socket] = None

        try:
            sock = create_server_sock(
                (self.listen_address, self.listen_port),
                transparent=self.transparent,
            )
        except PermissionError as permerror:
            if self.transparent and permerror.errno == 1:
                logging.error(
                    "%s Note: running SSH-MITM in transparent mode requires root privileges",
                    Colors.stylize("error creating socket!", fg("red") + attr("bold")),
                )
            elif permerror.errno == 13 and self.listen_port < 1024:
                logging.error(
                    "%s Note: running SSH-MITM on a port < 1024 requires root privileges",
                    Colors.stylize("error creating socket!", fg("red") + attr("bold")),
                )
            else:
                logging.exception(
                    "%s - unknown error",
                    Colors.stylize("error creating socket!", fg("red") + attr("bold")),
                )
            return
        if sock is None:
            logging.error(
                "%s", Colors.stylize("error creating socket!", fg("red") + attr("bold"))
            )
            return

        self.running = True
        try:
            while self.running:
                readable = select.select([sock], [], [], self.SELECT_TIMEOUT)[0]
                if len(readable) == 1 and readable[0] is sock:
                    client, addr = sock.accept()
                    remoteaddr = client.getsockname()
                    thread = threading.Thread(
                        target=self.create_session, args=(client, addr, remoteaddr)
                    )
                    thread.start()
                    self._threads.append(thread)
        except KeyboardInterrupt:
            self.running = False
            if sys.stdout.isatty():
                sys.stdout.write("\b\b\r")
                sys.stdout.flush()
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Error creating socket!")
        finally:
            logging.info(
                "%s %s",
                Colors.emoji("exclamation"),
                Colors.stylize("Shutting down server ...", fg("red")),
            )
            # TODO @manfred-kaiser: better shutdown for threads. At the moment we kill the server
            # https://github.com/ssh-mitm/ssh-mitm/issues/167
            # sock.close()  # noqa: ERA001
            # for thread in self._threads[:]:
            #    thread.join()  # noqa: ERA001
            os._exit(os.EX_OK)

    def create_session(
        self,
        client: socket,
        addr: Union[Tuple[str, int], Tuple[str, int, int, int]],
        remoteaddr: Union[Tuple[str, int], Tuple[str, int, int, int]],
    ) -> None:
        try:
            with self.session_class(
                self, client, addr, self.authenticator, remoteaddr, self.banner_name
            ) as session:
                logging.debug(
                    "incoming connection from %s to %s", str(addr), remoteaddr
                )
                if session.start():
                    logging.debug("DEBUG: Session started successfully, entering main loop")
                    loop_start_time = time.time()
                    first_iteration = True
                    while session.running:
                        # Reduce delay on first iteration for servers with quick timeouts (like ConfD)
                        # No delay at all for NETCONF to prevent connection drops
                        if first_iteration:
                            if session.netconf_requested:
                                time.sleep(0.001)  # Almost no delay for NETCONF
                            else:
                                time.sleep(0.01)  # Short delay for SSH
                            first_iteration = False
                        else:
                            time.sleep(0.1)
                        elapsed = time.time() - loop_start_time
                        logging.debug("DEBUG: Main loop (elapsed=%.2fs) - ssh_requested=%s, scp_requested=%s, sftp_requested=%s, netconf_requested=%s", 
                                     elapsed, session.ssh_requested, session.scp_requested, session.sftp_requested, session.netconf_requested)
                        if session.ssh_requested and self.ssh_interface:
                            logging.debug("DEBUG: SSH requested - starting ssh_interface: %s", self.ssh_interface)
                            session.ssh_requested = False
                            try:
                                logging.debug("DEBUG: Pre-forwarder session state - ssh_client=%s", session.ssh_client)
                                if session.ssh_client:
                                    logging.debug("DEBUG: ssh_client.transport=%s", session.ssh_client.transport)
                                    if session.ssh_client.transport:
                                        logging.debug("DEBUG: transport.is_active()=%s", session.ssh_client.transport.is_active())
                                logging.debug("DEBUG: Creating ssh_interface instance")
                                ssh_forwarder = self.ssh_interface(session)
                                logging.debug("DEBUG: ssh_interface instance created: %s", ssh_forwarder)
                                logging.debug("DEBUG: Calling forward() method")
                                ssh_forwarder.forward()
                                logging.debug("DEBUG: forward() method completed")
                            except Exception as e:
                                logging.error("DEBUG: Error in ssh_interface: %s", e)
                                logging.exception("DEBUG: Full traceback:")
                        elif session.scp_requested and self.scp_interface:
                            session.scp_requested = False
                            scp_interface = self.scp_interface(session)
                            thread = threading.Thread(target=scp_interface.forward)
                            thread.start()
                        elif session.netconf_requested and self.netconf_interface:
                            logging.debug("DEBUG: NETCONF requested - starting netconf_interface: %s", self.netconf_interface)
                            session.netconf_requested = False
                            try:
                                logging.debug("DEBUG: Pre-netconf forwarder session state - ssh_client=%s", session.ssh_client)
                                if session.ssh_client:
                                    logging.debug("DEBUG: ssh_client.transport=%s", session.ssh_client.transport)
                                    if session.ssh_client.transport:
                                        logging.debug("DEBUG: transport.is_active()=%s", session.ssh_client.transport.is_active())
                                logging.debug("DEBUG: Creating netconf_interface instance")
                                netconf_interface = self.netconf_interface(session)
                                logging.debug("DEBUG: netconf_interface instance created: %s", netconf_interface)
                                logging.debug("DEBUG: Starting netconf thread")
                                thread = threading.Thread(target=netconf_interface.forward)
                                thread.start()
                                logging.debug("DEBUG: NETCONF thread started")
                            except Exception as e:
                                logging.error("DEBUG: Error in netconf_interface: %s", e)
                                logging.exception("DEBUG: Full netconf traceback:")

                else:
                    logging.warning("(%s) session not started", session)
                    self._threads.remove(threading.current_thread())
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("error handling session creation")
