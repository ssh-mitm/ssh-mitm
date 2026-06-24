import logging
import os
import select
import sys
import threading
import time
import io
from binascii import hexlify
from dataclasses import dataclass, field
from pathlib import Path
from socket import socket

from colored import attr, fg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from paramiko import ECDSAKey, Ed25519Key, PKey, RSAKey, Transport
from paramiko.ssh_exception import SSHException
from rich import print as rich_print

from sshmitm import __version__ as ssh_mitm_version
from sshmitm.authentication import Authenticator, AuthenticatorPassThrough
from sshmitm.console import sshconsole
from sshmitm.exceptions import KeyGenerationError
from sshmitm.state import get_state_dir
from sshmitm.forwarders.agent import (
    AgentBaseForwarder,
    AgentForwarder,
    AgentLocalSocket,
    AgentProxy,
)
from sshmitm.forwarders.netconf import NetconfBaseForwarder, NetconfForwarder
from sshmitm.forwarders.powershell import (
    PowerShellBaseForwarder,
    PowerShellForwarder,
)
from sshmitm.forwarders.scp import SCPBaseForwarder, SCPForwarder
from sshmitm.forwarders.sftp import SFTPHandlerBasePlugin, SFTPHandlerPlugin
from sshmitm.forwarders.ssh import SSHBaseForwarder, SSHForwarder
from sshmitm.forwarders.tunnel import (
    LocalPortForwardingForwarder,
    RemotePortForwardingForwarder,
)
from sshmitm.interfaces.server import (
    BaseServerInterface,
    ProxyNetconfServer,
    ProxyPowerShellServer,
    ProxySFTPServer,
    ServerInterface,
)
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface
from sshmitm.moduleparser.colors import Colors
from sshmitm.multisocket import create_server_sock
from sshmitm.plugins.session import key_negotiation
from sshmitm.session import Session
from sshmitm.utils import SSHPubKey


_ALGO_CLASS: dict[str, type[PKey]] = {
    "rsa": RSAKey,
    "ecdsa": ECDSAKey,
    "ed25519": Ed25519Key,
}

_ALGO_STATE_FILE: dict[str, str] = {
    "rsa": "host_key_rsa",
    "ecdsa": "host_key_ecdsa",
    "ed25519": "host_key_ed25519",
}


@dataclass
class HostKeyEntry:
    key: PKey
    path: Path | None
    was_generated: bool


class SSHProxyServer:
    SELECT_TIMEOUT = 0.5

    def __init__(  # pylint: disable=too-many-arguments
        self,
        listen_address: str,
        listen_port: int,
        *,
        key_algorithms: list[str] | None = None,
        key_file_rsa: str | None = None,
        key_file_ecdsa: str | None = None,
        key_file_ed25519: str | None = None,
        key_rsa_length: int = 2048,
        ssh_interface: type[SSHBaseForwarder] = SSHForwarder,
        scp_interface: type[SCPBaseForwarder] = SCPForwarder,
        netconf_interface: type[NetconfBaseForwarder] = NetconfForwarder,
        powershell_interface: type[PowerShellBaseForwarder] = PowerShellForwarder,
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
        agent_forwarder: type[AgentBaseForwarder] = AgentForwarder,
        banner_name: str | None = None,
        debug: bool = False,
    ) -> None:
        self._threads: list[threading.Thread] = []
        self._host_key_entries: list[HostKeyEntry] = []
        self._key_algorithms: list[str] = key_algorithms or ["rsa", "ecdsa", "ed25519"]
        self._key_files: dict[str, str | None] = {
            "rsa": key_file_rsa,
            "ecdsa": key_file_ecdsa,
            "ed25519": key_file_ed25519,
        }
        self._key_rsa_length: int = key_rsa_length

        self.listen_port = listen_port
        self.listen_address = listen_address
        self.running = False

        self.ssh_interface: type[SSHBaseForwarder] = ssh_interface
        self.scp_interface: type[SCPBaseForwarder] = scp_interface
        self.netconf_interface: type[NetconfBaseForwarder] = netconf_interface
        self.powershell_interface: type[PowerShellBaseForwarder] = powershell_interface
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
        self.agent_forwarder: type[AgentBaseForwarder] = agent_forwarder
        self.banner_name: str | None = banner_name
        self.debug: bool = debug

        self.setup_host_keys()

    def print_serverinfo(self, json_log: bool = False) -> None:
        if not self._host_key_entries:
            return

        entries_data = []
        for entry in self._host_key_entries:
            pub = SSHPubKey(entry.key)
            if entry.path is not None:
                origin = "generated" if entry.was_generated else "loaded"
                location = str(entry.path)
            else:
                origin = "temporary"
                location = ""
            entries_data.append({
                "origin": origin,
                "location": location,
                "algorithm": type(entry.key).__name__,
                "bits": entry.key.get_bits(),
                "md5": pub.hash_md5(),
                "sha256": pub.hash_sha256(),
                "sha512": pub.hash_sha512(),
            })

        if json_log or not sys.stdout.isatty():
            logging.info("ssh-mitm server info", extra={"serverinfo": {
                "host_keys": entries_data,
                "listen_address": self.listen_address,
                "listen_port": self.listen_port,
                "transparent_mode": self.transparent,
            }})
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

            rich_print("[bold blue]:key: SSH-Host-Keys:[/bold blue]")
            for d in entries_data:
                if d["origin"] == "temporary":
                    rich_print(
                        f"   [yellow]:warning: {d['algorithm']} {d['bits']} bit — temporary (not persisted, changes on every restart)[/yellow]"
                    )
                elif d["origin"] == "generated":
                    rich_print(
                        f"   [green]:floppy_disk: {d['algorithm']} {d['bits']} bit — generated, saved to[/green] [bold]{d['location']}[/bold]"
                    )
                else:
                    rich_print(
                        f"   [green]:white_check_mark: {d['algorithm']} {d['bits']} bit — loaded from[/green] [bold]{d['location']}[/bold]"
                    )
                print(  # pylint: disable=consider-using-f-string
                    "   {sha256}\n"
                    "   {md5}".format(
                        sha256=Colors.stylize(d["sha256"], fg("light_blue") + attr("bold")),
                        md5=Colors.stylize(d["md5"], fg("light_blue") + attr("bold")),
                    )
                )
            sshconsole.rule(characters=".", style="bright_black")
            print(
                "{servericon} listen interfaces {listen_address} on port {listen_port}".format(
                    servericon=Colors.emoji("computer"),
                    listen_address=self.listen_address,
                    listen_port=self.listen_port,
                )
            )
            if self.transparent:
                rich_print(
                    ":exclamation: Transparent mode enabled [red bold](experimental)"
                )
            if self.debug:
                rich_print("[bold red]:exclamation: Debug mode enabled")
            rich_print(
                ":mortar_board: [bold]New to SSH-MITM?[/bold] Run [bold cyan]ssh-mitm tutorial[/bold cyan] for an interactive, browser-based introduction."
            )
            sshconsole.rule("[red]waiting for connections", style="red")

    def setup_host_keys(self) -> None:
        if not self._key_algorithms:
            logging.error("no host key algorithms configured")
            sys.exit(1)
        state_dir = get_state_dir()
        for algo in self._key_algorithms:
            if algo not in _ALGO_CLASS:
                logging.error("unsupported host key algorithm: %s", algo)
                sys.exit(1)
            self._setup_key_for_algo(algo, self._key_files.get(algo), state_dir)
        if not self._host_key_entries:
            logging.error("no host keys could be set up")
            sys.exit(1)

    def _setup_key_for_algo(
        self, algo: str, explicit_path: str | None, state_dir: Path | None
    ) -> None:
        if explicit_path:
            key_path = Path(explicit_path)
            if key_path.is_file():
                key = self._load_pkey(key_path)
                self._host_key_entries.append(HostKeyEntry(key=key, path=key_path, was_generated=False))
            else:
                key = self._generate_and_persist_pkey(algo, key_path)
                self._host_key_entries.append(HostKeyEntry(key=key, path=key_path, was_generated=True))
        elif state_dir is not None:
            key_path = state_dir / _ALGO_STATE_FILE[algo]
            if key_path.is_file():
                key = self._load_pkey(key_path)
                self._host_key_entries.append(HostKeyEntry(key=key, path=key_path, was_generated=False))
            else:
                key = self._generate_and_persist_pkey(algo, key_path)
                self._host_key_entries.append(HostKeyEntry(key=key, path=key_path, was_generated=True))
        else:
            key = self._generate_temp_pkey(algo)
            self._host_key_entries.append(HostKeyEntry(key=key, path=None, was_generated=True))

    def _generate_and_persist_pkey(self, algo: str, key_path: Path) -> PKey:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if algo == "ed25519":
                # paramiko 5.x Ed25519Key lacks write_private_key_file support;
                # write the OpenSSH PEM directly and reload from disk.
                pem = Ed25519PrivateKey.generate().private_bytes(
                    Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
                )
                key_path.write_bytes(pem)
                key_path.chmod(0o600)
                return Ed25519Key.from_private_key_file(str(key_path))
            if algo == "rsa":
                key: PKey = RSAKey.generate(bits=self._key_rsa_length)
            elif algo == "ecdsa":
                key = ECDSAKey.generate()
            else:
                msg = f"unsupported algorithm: {algo}"
                raise KeyGenerationError(msg)
            key.write_private_key_file(str(key_path))
            key_path.chmod(0o600)
            return key
        except ValueError as err:
            logging.error("failed to generate %s key: %s", algo, err)
            raise KeyGenerationError from err

    def _generate_temp_pkey(self, algo: str) -> PKey:
        try:
            if algo == "rsa":
                return RSAKey.generate(bits=self._key_rsa_length)
            if algo == "ecdsa":
                return ECDSAKey.generate()
            if algo == "ed25519":
                pem = Ed25519PrivateKey.generate().private_bytes(
                    Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
                )
                return Ed25519Key.from_private_key(io.StringIO(pem.decode()))
        except ValueError as err:
            logging.error("failed to generate %s key: %s", algo, err)
            raise KeyGenerationError from err
        msg = f"unsupported algorithm: {algo}"
        raise KeyGenerationError(msg)

    def _load_pkey(self, key_path: Path) -> PKey:
        for pkey_class in (RSAKey, ECDSAKey, Ed25519Key):
            try:
                return self._key_from_filepath(str(key_path), pkey_class, None)
            except SSHException:
                pass
        logging.error("host key format not supported: %s", key_path)
        raise KeyGenerationError

    def _key_from_filepath(
        self, filename: str, klass: type[PKey], password: str | None
    ) -> PKey:
        cert_suffix = "-cert.pub"
        if filename.endswith(cert_suffix):
            key_path = filename[: -len(cert_suffix)]
            cert_path = filename
        else:
            key_path = filename
            cert_path = filename + cert_suffix
        key = klass.from_private_key_file(key_path, password)
        hexlify(key.get_fingerprint())
        if os.path.isfile(cert_path):
            key.load_certificate(cert_path)
        return key

    @property
    def host_keys(self) -> list[PKey]:
        return [entry.key for entry in self._host_key_entries]

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

    def register_subsystem_handlers(
        self, transport: Transport, session: Session
    ) -> None:
        transport.set_subsystem_handler(
            name="sftp",
            handler=ProxySFTPServer,
            sftp_si=self.sftp_interface,
            session=session,
        )
        transport.set_subsystem_handler(
            "netconf", ProxyNetconfServer, self.netconf_interface, session
        )
        transport.set_subsystem_handler(
            "powershell", ProxyPowerShellServer, self.powershell_interface, session
        )

    def create_agent_proxy(self, transport: Transport) -> AgentProxy:
        return AgentProxy(transport)

    def create_agent_local_socket(self, transport: Transport) -> AgentLocalSocket:
        return AgentLocalSocket(transport)

    def create_agent_forwarder(self, session: Session) -> AgentBaseForwarder:
        return self.agent_forwarder(session)

    def _resolve_max_connections(self) -> int:
        # ``args`` is an instance attribute set in BaseModule.__init__, so it is
        # not available on the session class itself. Resolve the configured
        # max-connections value once from the parsed CLI arguments instead.
        try:
            session_args, _ = self.session_class.parser().parse_known_args()
            return int(getattr(session_args, "max_connections", 100))
        except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
            return 100

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
                    self._threads = [t for t in self._threads if t.is_alive()]
                    max_connections = self._resolve_max_connections()
                    if max_connections and len(self._threads) >= max_connections:
                        logging.warning(
                            "max connections reached (%d), rejecting connection from %s",
                            max_connections,
                            addr,
                        )
                        client.close()
                    else:
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
            self.running = False
            logging.info(
                "%s %s",
                Colors.emoji("exclamation"),
                Colors.stylize("Shutting down server ...", fg("red")),
            )
            if sock is not None:
                sock.close()
            shutdown_timeout = 30
            deadline = time.monotonic() + shutdown_timeout
            for thread in list(self._threads):
                wait = max(0.0, deadline - time.monotonic())
                thread.join(timeout=wait)
            still_alive = [t for t in self._threads if t.is_alive()]
            if still_alive:
                logging.warning(
                    "%d session thread(s) did not stop within %ds, forcing exit",
                    len(still_alive),
                    shutdown_timeout,
                )
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
                            handler_entry = session.scp.handler_entry
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
