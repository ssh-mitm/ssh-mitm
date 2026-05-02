import logging
import os
import select
import sys
import threading
import time
from binascii import hexlify
from socket import socket

import paramiko
from colored import attr, fg
from paramiko import ECDSAKey, Ed25519Key, PKey, RSAKey, Transport
from paramiko.ssh_exception import SSHException
from rich import print as rich_print

from sshmitm import __version__ as ssh_mitm_version
from sshmitm.authentication import Authenticator, AuthenticatorPassThrough
from sshmitm.console import sshconsole
from sshmitm.exceptions import KeyGenerationError
from sshmitm.forwarders.agent import AgentLocalSocket, AgentProxy
from sshmitm.forwarders.netconf import NetconfBaseForwarder, NetconfForwarder
from sshmitm.forwarders.scp import SCPBaseForwarder, SCPForwarder
from sshmitm.forwarders.sftp import SFTPHandlerBasePlugin, SFTPHandlerPlugin
from sshmitm.forwarders.ssh import SSHBaseForwarder, SSHForwarder
from sshmitm.forwarders.tunnel import (
    LocalPortForwardingForwarder,
    RemotePortForwardingForwarder,
)
from sshmitm.interfaces.server import BaseServerInterface, ProxyNetconfServer, ProxySFTPServer, ServerInterface
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface
from sshmitm.moduleparser.colors import Colors
from sshmitm.multisocket import create_server_sock
from sshmitm.plugins.session import key_negotiation
from sshmitm.session import Session
from sshmitm.utils import SSHPubKey


class SSHProxyServer:
    SELECT_TIMEOUT = 0.5

    def __init__(  # pylint: disable=too-many-arguments
        self,
        listen_address: str,
        listen_port: int,
        *,
        key_file: str | None = None,
        key_algorithm: str = "rsa",
        key_length: int = 2048,
        ssh_interface: type[SSHBaseForwarder] = SSHForwarder,
        scp_interface: type[SCPBaseForwarder] = SCPForwarder,
        netconf_interface: type[NetconfBaseForwarder] = NetconfForwarder,
        sftp_interface: type[BaseSFTPServerInterface] = SFTPProxyServerInterface,
        sftp_handler: type[SFTPHandlerBasePlugin] = SFTPHandlerPlugin,
        server_tunnel_interface: type[
            RemotePortForwardingForwarder
        ] = RemotePortForwardingForwarder,
        client_tunnel_interface: type[
            LocalPortForwardingForwarder
        ] = LocalPortForwardingForwarder,
        authentication_interface: type[BaseServerInterface] = ServerInterface,
        authenticator: type[Authenticator] = AuthenticatorPassThrough,
        transparent: bool = False,
        session_class: type[Session] = Session,
        banner_name: str | None = None,
        expose_agent_socket: bool = False,
        debug: bool = False,
    ) -> None:
        self._threads: list[threading.Thread] = []
        self._hostkey: PKey | None = None

        self.listen_port = listen_port
        self.listen_address = listen_address
        self.running = False

        self.key_file: str | None = key_file
        self.key_algorithm: str = key_algorithm
        self.key_algorithm_class: type[PKey] | None = None
        self.key_length: int = key_length

        self.ssh_interface: type[SSHBaseForwarder] = ssh_interface
        self.scp_interface: type[SCPBaseForwarder] = scp_interface
        self.netconf_interface: type[NetconfBaseForwarder] = netconf_interface
        self.sftp_handler: type[SFTPHandlerBasePlugin] = sftp_handler
        self.sftp_interface: type[BaseSFTPServerInterface] = (
            self.sftp_handler.get_interface() or sftp_interface
        )
        self.server_tunnel_interface: type[RemotePortForwardingForwarder] = (
            server_tunnel_interface
        )
        self.client_tunnel_interface: type[LocalPortForwardingForwarder] = (
            client_tunnel_interface
        )
        # Server Interface
        self.authentication_interface: type[BaseServerInterface] = (
            authentication_interface
        )
        self.authenticator: type[Authenticator] = authenticator
        self.transparent: bool = transparent
        self.session_class: type[Session] = session_class
        self.banner_name: str | None = banner_name
        self.expose_agent_socket: bool = expose_agent_socket
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
                self._hostkey = self.key_algorithm_class.generate(  # type: ignore[union-attr]
                    bits=key_algorithm_bits or 2048
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
        self, filename: str, klass: type[PKey], password: str | None
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
    def host_key(self) -> PKey | None:
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

    def setup_transport_hooks(self, session: Session) -> None:
        key_negotiation.handle_key_negotiation(session)

    def register_subsystem_handlers(self, transport: Transport, session: Session) -> None:
        transport.set_subsystem_handler(
            name="sftp",
            handler=ProxySFTPServer,
            sftp_si=self.sftp_interface,
            session=session,
        )
        transport.set_subsystem_handler(
            "netconf", ProxyNetconfServer, self.netconf_interface, session
        )

    def create_agent_proxy(self, transport: Transport) -> AgentProxy:
        return AgentProxy(transport)

    def create_agent_local_socket(self, transport: Transport) -> AgentLocalSocket:
        return AgentLocalSocket(transport)

    def start(self) -> None:
        self._clean_environment()
        sock: socket | None = None

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
        addr: tuple[str, int] | tuple[str, int, int, int],
        remoteaddr: tuple[str, int] | tuple[str, int, int, int],
    ) -> None:
        try:
            with self.session_class(
                self,
                client,
                addr,
                self.authenticator,
                remoteaddr,
                self.banner_name,
            ) as session:
                logging.debug(
                    "incoming connection from %s to %s", str(addr), remoteaddr
                )
                if session.start():
                    while session.running:
                        time.sleep(0.1)
                        if session.ssh.requested and self.ssh_interface:
                            session.ssh.requested = False
                            self.ssh_interface(session).forward()
                        elif session.scp.requested and self.scp_interface:
                            session.scp.requested = False
                            handler_entry = SCPBaseForwarder.get_exec_handler(
                                session.scp.command
                            )
                            interface_class = (
                                handler_entry.handler
                                if handler_entry is not None
                                else self.scp_interface
                            )
                            scp_interface = interface_class(session)
                            thread = threading.Thread(target=scp_interface.forward)
                            thread.start()
                        elif session.netconf.requested and self.netconf_interface:
                            session.netconf.requested = False
                            netconf_interface = self.netconf_interface(session)
                            thread = threading.Thread(target=netconf_interface.forward)
                            thread.start()

                else:
                    logging.warning("(%s) session not started", session)
                    self._threads.remove(threading.current_thread())
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("error handling session creation")
