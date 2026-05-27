import logging
import os
import queue
import socket
import sys
import threading
from abc import abstractmethod
from collections.abc import Callable
from types import TracebackType
from typing import TYPE_CHECKING, Self

import paramiko
from colored.colored import attr, fg
from paramiko import PKey

from sshmitm.clients.ssh import AuthenticationMethod, SSHClient
from sshmitm.exceptions import MissingHostException
from sshmitm.moduleparser.colors import Colors
from sshmitm.modules import SSHMITMBaseModule
from sshmitm.utils import SSHPubKey

if TYPE_CHECKING:
    import sshmitm


class PublicKeyEnumerationError(Exception):
    pass


class PublicKeyEnumerator:
    """Probe a remote host to determine if the provided public key is authorized for the provided username.

    The PublicKeyEnumerator takes four arguments: hostname_or_ip (a string representing hostname
    or IP address), port (an integer representing the port number), username (a string
    representing the username), and public_key (a public key in paramiko.pkey.PublicBlob format).
    The function returns a boolean indicating if the provided public key is authorized or not.

    The PublicKeyEnumerator uses the paramiko library to perform the probe by creating a secure shell (SSH)
    connection to the remote host and performing authentication using the provided username and
    public key. Two helper functions, valid and parse_service_accept, are defined inside the
    check_publickey function to assist with the authentication process.

    The PublicKeyEnumerator function opens a socket connection to the remote host and starts an
    SSH transport using the paramiko library. The function then generates a random private
    key, replaces the public key with the provided key, and performs the public key
    using transport.auth_publickey. The result of the authentication is stored in the
    valid_key variable. If the authentication fails, an exception of type
    paramiko.ssh_exception.AuthenticationException is raised and caught, leaving the
    valid_key variable as False. Finally, the function returns the value of valid_key,
    which indicates whether the provided public key is authorized or not.
    """

    def __init__(
        self,
        hostname_or_ip: str = "",
        port: int = 0,
        *,
        existing_transport: paramiko.transport.Transport | None = None,
    ) -> None:
        self.remote_address = (hostname_or_ip, port)
        self._owns_transport: bool = existing_transport is None
        self._service_ready: threading.Event = threading.Event()
        if existing_transport is not None:
            self.sock: socket.socket | None = None
            self.transport: paramiko.transport.Transport | None = existing_transport
            self.connected: bool = True
        else:
            self.sock = None
            self.transport = None
            self.connected = False

    def mark_service_ready(self) -> None:
        """Signal that the ssh-userauth service is already active (e.g. after a prior auth_none call)."""
        self._service_ready.set()

    def connect(self) -> None:
        if self.connected:
            return
        self.connected = True
        self._service_ready.clear()
        self.sock = socket.create_connection(self.remote_address)
        self.transport = paramiko.transport.Transport(self.sock)
        self.transport.start_client()

    def close(self) -> None:
        self.connected = False
        if not self._owns_transport:
            return
        if self.transport is not None:
            self.transport.close()
        if self.sock is not None:
            self.sock.close()

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def _rsa_algorithm(self) -> str:
        if self.transport is None:
            return "rsa-sha2-512"
        server_sig_algs = self.transport.server_extensions.get("server-sig-algs", b"").decode()  # type: ignore[attr-defined]
        for algo in ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"):
            if algo in server_sig_algs:
                return algo
        return "rsa-sha2-512"

    def check_publickey(
        self, username: str, public_key: str | paramiko.pkey.PublicBlob
    ) -> bool:
        # pylint: disable=protected-access
        if not self.connected:
            self.connect()
        if not self.transport:
            msg = "enumerator not connected! use connect() method before enumeration."
            raise PublicKeyEnumerationError(msg)

        public_blob = (
            public_key
            if isinstance(public_key, paramiko.pkey.PublicBlob)
            else paramiko.pkey.PublicBlob.from_string(public_key)
        )
        key_type = public_blob.key_type
        if key_type == "ssh-rsa":
            key_type = self._rsa_algorithm()

        result_event = threading.Event()
        valid_key = [False]

        def handle_pk_ok(msg: paramiko.message.Message) -> None:
            valid_key[0] = True
            result_event.set()

        def handle_failure(msg: paramiko.message.Message) -> None:
            result_event.set()

        # Register per-instance handlers — no global state, no lock needed.
        # transport._handler_table is checked before auth_handler._handler_table.
        self.transport._handler_table[paramiko.common.MSG_USERAUTH_PK_OK] = handle_pk_ok  # type: ignore[index]
        self.transport._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = handle_failure  # type: ignore[index]

        if not self._service_ready.is_set():
            def handle_service_accept(msg: paramiko.message.Message) -> None:
                if msg.get_text() == "ssh-userauth":
                    self._service_ready.set()

            self.transport._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = handle_service_accept  # type: ignore[index]

            m = paramiko.message.Message()
            m.add_byte(paramiko.common.cMSG_SERVICE_REQUEST)
            m.add_string("ssh-userauth")
            self.transport._send_message(m)  # type: ignore[attr-defined]

            if not self._service_ready.wait(timeout=10):
                raise PublicKeyEnumerationError("SSH service request timed out")

        # RFC 4252 §7: probe without signature — server replies with PK_OK (60) or FAILURE (51)
        m = paramiko.message.Message()
        m.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string("ssh-connection")
        m.add_string("publickey")
        m.add_boolean(False)
        m.add_string(key_type)
        m.add_string(public_blob.key_blob)
        self.transport._send_message(m)  # type: ignore[attr-defined]

        result_event.wait(timeout=10)
        return valid_key[0]


class KeyboardInteractiveBridge:
    """Thread-safe queue-based bridge for RFC 4256 keyboard-interactive passthrough.

    The remote auth thread calls remote_handler() each challenge round (blocking until
    the client responds). The MITM server-side calls get_next_challenge() to receive
    prompts and send_responses() to unblock the handler. set_auth_result() is called
    once when the remote auth exchange completes.
    """

    def __init__(self) -> None:
        self._challenge_queue: queue.Queue[tuple] = queue.Queue()
        self._response_queue: queue.Queue[list[str]] = queue.Queue()

    def remote_handler(
        self,
        title: str,
        instructions: str,
        prompt_list: list[tuple[str, bool]],
    ) -> list[str]:
        """Called by paramiko in the remote auth thread for each challenge round."""
        prompts = [(str(p), bool(e)) for p, e in prompt_list]
        self._challenge_queue.put(("challenge", title, instructions, prompts))
        try:
            return self._response_queue.get(timeout=60)
        except queue.Empty:
            logging.warning("keyboard-interactive: timeout waiting for client responses")
            return []

    def set_auth_result(self, success: bool) -> None:
        """Signal auth completion to the MITM server-side."""
        result = paramiko.common.AUTH_SUCCESSFUL if success else paramiko.common.AUTH_FAILED
        self._challenge_queue.put(("result", result))

    def get_next_challenge(self, timeout: float = 30.0) -> tuple | None:
        """Wait for the next event: ("challenge", title, instructions, prompts) or ("result", int)."""
        try:
            return self._challenge_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def send_responses(self, responses: list[str]) -> None:
        """Provide client responses to unblock the remote_handler."""
        self._response_queue.put(responses)


class RemoteCredentials:
    """
    The `RemoteCredentials` class represents the credentials required to access a remote host.
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        *,
        username: str,
        password: str | None = None,
        key: PKey | None = None,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        """
        The `__init__` method is the constructor of the class and it is used to initialize the attributes of the class.

        :param username: (str) a string representing the username of the remote host. This is a required argument and must be specified when creating an instance of the class.
        :param password: (str) an optional string representing the password of the remote host. This argument is optional and if not specified, the value will be `None`.
        :param key: (PKey) an optional `PKey` object representing a private key used to authenticate with the remote host. This argument is optional and if not specified, the value will be `None`.
        :param host: (str) an optional string representing the hostname or IP address of the remote host. This argument is optional and if not specified, the value will be `None`.
        :param port: (int) an optional integer representing the port number used to connect to the remote host. This argument is optional and if not specified, the value will be `None`.
        """
        self.username: str = username
        """
        (str) a string representing the username of the remote host.
        """

        self.password: str | None = password
        """
        (str) an optional string representing the password of the remote host. This argument is optional and if not specified, the value will be `None`.
        """

        self.key: PKey | None = key
        """
        (PKey) an optional `PKey` object representing a private key used to authenticate with the remote host. This argument is optional and if not specified, the value will be `None`.
        """

        self.host: str | None = host
        """
        (str) an optional string representing the hostname or IP address of the remote host. This argument is optional and if not specified, the value will be `None`.
        """

        self.port: int | None = port
        """
        (int) an optional integer representing the port number used to connect to the remote host. This argument is optional and if not specified, the value will be `None`.
        """

    @staticmethod
    def load_private_key(path: str, passphrase: str | None = None) -> paramiko.PKey:
        """
        Loads an OpenSSH private key from a file and returns a Paramiko PKey object.

        :param path: Path to the private key file (e.g., ~/.ssh/id_ed25519)
        :param passphrase: Optional password for encrypted keys
        :return: Instance of paramiko.PKey (e.g., RSAKey, Ed25519Key, ECDSAKey)
        :raises: paramiko.ssh_exception.SSHException for invalid or unknown key format
        """
        with open(path, encoding="utf-8") as f:
            f.read()

        key_classes: list[type[paramiko.PKey]] = [
            paramiko.Ed25519Key,
            paramiko.ECDSAKey,
            paramiko.RSAKey,
        ]
        for key_cls in key_classes:
            try:
                return key_cls.from_private_key_file(path, password=passphrase)
            except (  # `try`-`except` within a loop incurs performance overhead
                paramiko.SSHException
            ):
                continue

        msg = "Unbekanntes oder ungültiges Schlüsselformat."
        raise paramiko.SSHException(msg)


class Authenticator(SSHMITMBaseModule):
    """Specifies the authenticator module used for validating user credentials and managing authentication workflows."""

    @classmethod
    def parser_arguments(cls) -> None:
        """
        Adds the options for remote authentication using argparse.
        """
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--remote-host",
            dest="remote_host",
            help="remote host to connect to (default 127.0.0.1)",
        )
        plugin_group.add_argument(
            "--remote-port",
            type=int,
            dest="remote_port",
            help="remote port to connect to (default 22)",
        )
        plugin_group.add_argument(
            "--remote-fingerprints",
            type=str,
            dest="remote_fingerprints",
            help="comma-separated fingerprints; empty disables check",
        )
        plugin_group.add_argument(
            "--disable-remote-fingerprint-warning",
            dest="disable_remote_fingerprint_warning",
            action="store_true",
            help="disables the warning if no remote fingerprints are provided",
        )
        plugin_group.add_argument(
            "--auth-username",
            dest="auth_username",
            help="username for remote authentication",
        )
        plugin_group.add_argument(
            "--auth-password",
            dest="auth_password",
            help="password for remote authentication",
        )
        plugin_group.add_argument(
            "--auth-key",
            dest="auth_key",
            help="ssh private key for remote authentication",
        )

        plugin_group.add_argument(
            "--hide-credentials",
            dest="auth_hide_credentials",
            action="store_true",
            help="do not log credentials (usefull for presentations)",
        )

        honeypot_group = cls.argument_group(
            "AuthenticationFallback",
            description=("Options for the authentication fallback to a honey pot"),
        )
        honeypot_group.add_argument(
            "--enable-auth-fallback",
            action="store_true",
            help="enabled the fallback to a hoenypot when authentication not possible",
        )
        honeypot_group.add_argument(
            "--fallback-host",
            dest="fallback_host",
            required="--enable-auth-fallback" in sys.argv,
            help="fallback host for the honeypot",
        )
        honeypot_group.add_argument(
            "--fallback-port",
            dest="fallback_port",
            type=int,
            help="fallback port for the honeypot",
        )
        honeypot_group.add_argument(
            "--fallback-username",
            dest="fallback_username",
            required="--enable-auth-fallback" in sys.argv,
            help="username for the honeypot",
        )
        honeypot_group.add_argument(
            "--fallback-password",
            dest="fallback_password",
            required="--enable-auth-fallback" in sys.argv,
            help="password for the honeypot",
        )

    def __init__(self, session: "sshmitm.session.Session") -> None:
        """
        Initializes Authenticator instance.

        This class pass the authentication from the client to the server.

        :param session: an object of sshmitm.session.Session class to store session information.
        """
        super().__init__()
        self.session = session
        self.session.register_session_thread()

    def get_preconnect_address(self) -> tuple[str, int] | None:
        if self.session.proxyserver.transparent:
            host = self.args.remote_host or self.session.remote.socket_address[0]
            port = self.args.remote_port or self.session.remote.socket_address[1]
        else:
            host = self.args.remote_host or "127.0.0.1"
            port = self.args.remote_port or 22
        return (str(host), int(port)) if host else None

    def get_remote_host_credentials(
        self, username: str, password: str | None = None, key: PKey | None = None
    ) -> RemoteCredentials:
        """
        Get the credentials for remote host.

        :param username: remote host username.
        :param password: remote host password.
        :param key: remote host private key.
        :return: an object of RemoteCredentials class.
        """
        if self.args.auth_key:
            key = RemoteCredentials.load_private_key(self.args.auth_key)
        if self.session.proxyserver.transparent:
            return RemoteCredentials(
                username=self.args.auth_username or username,
                password=self.args.auth_password or password,
                key=key,
                host=self.args.remote_host or self.session.remote.socket_address[0],
                port=self.args.remote_port or self.session.remote.socket_address[1],
            )
        return RemoteCredentials(
            username=self.args.auth_username or username,
            password=self.args.auth_password or password,
            key=key,
            host=self.args.remote_host or "127.0.0.1",
            port=self.args.remote_port or 22,
        )

    @abstractmethod
    def get_auth_methods(
        self, host: str, port: int, username: str | None = None
    ) -> list[str] | None:
        """
        Get the available authentication methods for a remote host.

        :param host: remote host address.
        :param port: remote host port.
        :param username: username which is used during authentication
        :return: a list of strings representing the available authentication methods.
        """

    def authenticate(
        self,
        username: str | None = None,
        password: str | None = None,
        key: PKey | None = None,
        store_credentials: bool = True,
    ) -> int:
        """
        Authenticate with the remote host using provided credentials.

        :param username: remote host username.
        :param password: remote host password.
        :param key: remote host private key.
        :param store_credentials: boolean flag to indicate if provided credentials should be stored.
        :return: integer representing authentication success or failure.
        """
        if store_credentials:
            self.session.auth.username_provided = username
            self.session.auth.password_provided = password
        if username:
            remote_credentials: RemoteCredentials = self.get_remote_host_credentials(
                username, password, key
            )
            self.session.auth.username = remote_credentials.username
            self.session.auth.password = remote_credentials.password
            self.session.auth.remote_key = remote_credentials.key
            self.session.remote.address = (
                remote_credentials.host,
                remote_credentials.port,
            )
        if key and not self.session.auth.remote_key:
            self.session.auth.remote_key = key

        if (
            self.session.remote.address[0] is None
            or self.session.remote.address[1] is None
        ):
            logging.error("no remote host")
            return paramiko.common.AUTH_FAILED

        try:
            if self.session.auth.agent:
                return self.auth_agent(
                    self.session.auth.username,
                    self.session.remote.address[0],
                    self.session.remote.address[1],
                )
            if self.session.auth.password:
                return self.auth_password(
                    self.session.auth.username,
                    self.session.remote.address[0],
                    self.session.remote.address[1],
                    self.session.auth.password,
                )
            if self.session.auth.remote_key:
                return self.auth_publickey(
                    self.session.auth.username,
                    self.session.remote.address[0],
                    self.session.remote.address[1],
                    self.session.auth.remote_key,
                )
        except MissingHostException:
            logging.error("no remote host")
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("internal error, abort authentication!")
        return paramiko.common.AUTH_FAILED

    @abstractmethod
    def auth_agent(self, username: str, host: str, port: int) -> int:
        """
        Performs authentication using the ssh-agent.
        """

    @abstractmethod
    def auth_password(self, username: str, host: str, port: int, password: str) -> int:
        """
        Performs authentication using a password.
        """

    @abstractmethod
    def auth_publickey(self, username: str, host: str, port: int, key: PKey) -> int:
        """
        Performs authentication using public key authentication.
        """

    def auth_fallback(self, username: str) -> int:
        """
        This method is executed when the intercepted client would be allowed to log in to the server,
        but due to the interception, the login is not possible.

        The method checks if a fallback host (a honeypot) has been provided and if not,
        it closes the session, and logs that authentication is not possible.
        If the fallback host has been provided, it attempts to log in to the honeypot using
        the username and password provided, and reports success or failure accordingly.
        If authentication against the honeypot fails, it logs an error message.
        """
        if not self.args.fallback_host:
            if self.session.auth.agent:
                logging.error(
                    "\n".join(
                        [
                            Colors.stylize(
                                Colors.emoji("exclamation")
                                + " ssh agent keys are not allowed for signing. Remote authentication not possible.",
                                fg("red") + attr("bold"),
                            ),
                            Colors.stylize(
                                Colors.emoji("information")
                                + " To intercept clients, you can provide credentials for a honeypot.",
                                fg("yellow") + attr("bold"),
                            ),
                        ]
                    )
                )
            else:
                logging.error(
                    "\n".join(
                        [
                            Colors.stylize(
                                Colors.emoji("exclamation")
                                + " ssh agent not forwarded. Login to remote host not possible with publickey authentication.",
                                fg("red") + attr("bold"),
                            ),
                            Colors.stylize(
                                Colors.emoji("information")
                                + " To intercept clients without a forwarded agent, you can provide credentials for a honeypot.",
                                fg("yellow") + attr("bold"),
                            ),
                        ]
                    )
                )
            return paramiko.common.AUTH_FAILED

        auth_status = self.connect(
            user=self.args.fallback_username or username,
            password=self.args.fallback_password,
            host=self.args.fallback_host,
            port=self.args.fallback_port,
            method=AuthenticationMethod.PASSWORD,
            run_post_auth=False,
        )
        if auth_status == paramiko.common.AUTH_SUCCESSFUL:
            logging.warning(
                Colors.stylize(
                    Colors.emoji("warning")
                    + " publickey authentication failed - no agent forwarded - connecting to honeypot!",
                    fg("yellow") + attr("bold"),
                ),
            )
        else:
            logging.error(
                Colors.stylize(
                    Colors.emoji("exclamation")
                    + " Authentication against honeypot failed!",
                    fg("red") + attr("bold"),
                ),
            )
        return auth_status

    def auth_keyboard_interactive(
        self,
        username: str,
        host: str,
        port: int,
        bridge: "KeyboardInteractiveBridge",
        submethods: str = "",
    ) -> int:
        """Perform keyboard-interactive auth with the remote server, proxying challenges via bridge."""
        return paramiko.common.AUTH_FAILED

    def connect(  # pylint: disable=too-many-arguments
        self,
        user: str,
        host: str,
        port: int,
        method: AuthenticationMethod,
        password: str | None = None,
        key: PKey | None = None,
        interactive_handler: Callable | None = None,
        interactive_submethods: str = "",
        *,
        run_post_auth: bool = True,
    ) -> int:
        """
        Connects to the SSH server and performs the necessary authentication.
        """
        if not host:
            raise MissingHostException

        if hasattr(self.session, "finalize_upstream_transport"):
            self.session.finalize_upstream_transport()

        auth_status = paramiko.common.AUTH_FAILED
        with self.session.ssh.client_created:
            upstream_transport = (
                # pylint: disable-next=protected-access
                self.session._upstream_transport
            )
            # pylint: disable-next=protected-access
            self.session._upstream_transport = None
            self.session.ssh.client = SSHClient(
                host,
                port,
                method,
                password,
                user,
                key,
                self.session,
                self.args.remote_fingerprints,
                self.args.disable_remote_fingerprint_warning,
                existing_transport=upstream_transport,
                interactive_handler=interactive_handler,
                interactive_submethods=interactive_submethods,
            )
            self.pre_auth_action()
            try:
                if (
                    self.session.ssh.client is not None
                    and self.session.ssh.client.connect()
                ):
                    auth_status = paramiko.common.AUTH_SUCCESSFUL
            except paramiko.SSHException:
                logging.error(
                    Colors.stylize(
                        "Connection to remote server refused", fg("red") + attr("bold")
                    )
                )
                return paramiko.common.AUTH_FAILED
            if run_post_auth:
                self.post_auth_action(auth_status == paramiko.common.AUTH_SUCCESSFUL)
            self.session.ssh.client_auth_finished = True
            self.session.ssh.client_created.notify_all()
        return auth_status

    def pre_auth_action(self) -> None:
        """Perform any pre-authentication actions.

        This method is called before the authentication process starts.
        """

    def post_auth_action(self, success: bool) -> None:
        """Perform any post-authentication actions.

        This method is called after the authentication process is completed, whether successfully or not.

        :param success: indicates if the authentication was successful or not
        """

    def on_session_close(self) -> None:
        """Performs actions when the session is closed."""


class AuthenticatorPassThrough(Authenticator):
    """A subclass of `Authenticator` which passes the authentication to the remote server.

    This class reuses the credentials received from the client and sends it directly to the remote server for authentication.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        super().parser_arguments()

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session=session)

        self.pubkey_enumerator: PublicKeyEnumerator | None = None
        self.pubkey_auth_success: bool = False
        self.valid_key: PKey | None = None

    def _make_pubkey_enumerator(self, host: str, port: int) -> PublicKeyEnumerator:
        if hasattr(self.session, "finalize_upstream_transport"):
            self.session.finalize_upstream_transport()
        upstream = getattr(self.session, "_upstream_transport", None)
        if isinstance(upstream, paramiko.Transport) and upstream.is_active():
            return PublicKeyEnumerator(existing_transport=upstream)
        enumerator = PublicKeyEnumerator(host, port)
        enumerator.connect()
        return enumerator

    def get_auth_methods(
        self, host: str, port: int, username: str | None = None
    ) -> list[str] | None:
        """
        Get the available authentication methods for a remote host.

        :param host: remote host address.
        :param port: remote host port.
        :param username: username which is used for authentication
        :return: a list of strings representing the available authentication methods.
        """
        if not self.pubkey_enumerator:
            self.pubkey_enumerator = self._make_pubkey_enumerator(host, port)

        auth_methods = None
        if not self.pubkey_enumerator.transport:
            msg = "pubkey_enumerator not initialized"
            raise PublicKeyEnumerationError(msg)
        try:
            self.pubkey_enumerator.transport.auth_none(username or "")
        except paramiko.BadAuthenticationType as err:
            auth_methods = err.allowed_types
        # ssh-userauth service is now active; skip the service request in check_publickey()
        self.pubkey_enumerator.mark_service_ready()
        return auth_methods

    def auth_agent(self, username: str, host: str, port: int) -> int:
        return self.connect(username, host, port, AuthenticationMethod.AGENT)

    def auth_keyboard_interactive(
        self,
        username: str,
        host: str,
        port: int,
        bridge: KeyboardInteractiveBridge,
        submethods: str = "",
    ) -> int:
        return self.connect(
            username,
            host,
            port,
            AuthenticationMethod.KEYBOARD_INTERACTIVE,
            interactive_handler=bridge.remote_handler,
            interactive_submethods=submethods,
        )

    def auth_password(self, username: str, host: str, port: int, password: str) -> int:
        return self.connect(
            username, host, port, AuthenticationMethod.PASSWORD, password=password
        )

    def auth_publickey(self, username: str, host: str, port: int, key: PKey) -> int:
        """
        Performs authentication using public key authentication.

        This method is checking if a user with a specific public key is allowed to log into a server
        using the SSH protocol. If the key can sign, the method will try to connect to the server
        using the public key. If the connection is successful, the user is considered authenticated.

        If the key cannot sign, the method will check if the key is valid for the host and port
        specified for the user. If the key is valid, the user is considered authenticated.

        If the key is not valid, or if there is any error while checking if the key is valid,
        the user will not be authenticated and will not be able to log in.
        """
        if not self.pubkey_enumerator:
            self.pubkey_enumerator = self._make_pubkey_enumerator(host, port)

        if key.can_sign():
            logging.debug(
                "AuthenticatorPassThrough.auth_publickey: username=%s, key=%s %s %sbits",
                username,
                key.get_name(),
                key.fingerprint,
                key.get_bits(),
            )
            return self.connect(
                username, host, port, AuthenticationMethod.PUBLICKEY, key=key
            )
        # A public key is only passed directly from check_auth_publickey.
        # In that case, we need to authenticate the client so that we can wait for the agent!
        publickey = paramiko.pkey.PublicBlob(key.get_name(), key.asbytes())
        try:
            # ssh sends first a publickey to check if this key is known.
            # to avoid a second key lookup, a valid key is stored and later during the
            # real authentication process, the key is compared with the known key.
            if self.pubkey_auth_success and self.valid_key == key:
                return paramiko.common.AUTH_SUCCESSFUL

            # this is only the pubkey lookup, which is done by all clients
            # we store the knwon key to avoid a second key lookup
            if self.pubkey_enumerator.check_publickey(username, publickey):
                logging.info(
                    "Found valid key for host %s:%s username=%s, key=%s %s %sbits",
                    host,
                    port,
                    username,
                    key.get_name(),
                    key.fingerprint,
                    key.get_bits(),
                )
                self.pubkey_auth_success = True
                self.valid_key = key
                return paramiko.common.AUTH_SUCCESSFUL
        except EOFError:
            logging.exception(
                "%s - faild to check if client is allowed to login with publickey authentication",
                self.session.sessionid,
            )
        return paramiko.common.AUTH_FAILED

    def post_auth_action(self, success: bool) -> None:  # noqa: C901
        """
        This method logs information about an authentication event.

        The success parameter determines whether the authentication was successful or not.
        If the authentication was successful, the log will show a message saying
        "Remote authentication succeeded".

        If not, the log will show "Remote authentication failed". The log will also show
        the remote address, username, and password used for authentication
        (if provided). Information about the accepted public key and remote public key
        (if any) will also be included in the log. If there is an agent available,
        the number of keys it has will be displayed, along with details about each key
        (name, hash, number of bits, and whether it can sign).

        All this information can be saved to a log file for later review.
        """

        def get_agent_pubkeys() -> list[SSHPubKey]:
            pubkeyfile_path = None

            keys_parsed: list[SSHPubKey] = []
            if self.session.auth.agent is None:
                return keys_parsed

            keys = self.session.auth.agent.get_keys()
            keys_parsed.extend(SSHPubKey(key) for key in keys)

            if self.session.session_log_dir:
                os.makedirs(self.session.session_log_dir, exist_ok=True)
                pubkeyfile_path = os.path.join(
                    self.session.session_log_dir, "publickeys"
                )
                with open(pubkeyfile_path, "a+", encoding="utf-8") as pubkeyfile:
                    for ssh_pub_key in keys_parsed:
                        comment = "saved-from-agent"
                        pubkeyfile.write(
                            f"{ssh_pub_key.get_name()} {ssh_pub_key.get_base64()} {comment}\n"
                        )

            return keys_parsed

        if self.pubkey_enumerator and self.pubkey_enumerator.connected:
            self.pubkey_enumerator.close()

        logmessage = []
        if success:
            logmessage.append(
                Colors.stylize(
                    "Remote authentication succeeded", fg("green") + attr("bold")
                )
            )
        else:
            logmessage.append(Colors.stylize("Remote authentication failed", fg("red")))

        if self.session.ssh.client is not None:
            logmessage.append(
                f"\tRemote Address: {self.session.ssh.client.host}:{self.session.ssh.client.port}"
            )
            logmessage.append(f"\tUsername: {self.session.auth.username_provided}")

        if self.session.auth.password_provided:
            display_password = None
            if not self.args.auth_hide_credentials:
                display_password = self.session.auth.password_provided
            logmessage.append(
                f"\tPassword: {display_password or Colors.stylize('*******', fg('dark_gray'))}"
            )

        if (
            self.session.auth.accepted_key is not None
            and self.session.auth.remote_key != self.session.auth.accepted_key
        ):
            logmessage.append(
                "\tAccepted-Publickey: "
                f"{self.session.auth.accepted_key.get_name()} {self.session.auth.accepted_key.fingerprint} {self.session.auth.accepted_key.get_bits()}bits"
            )

        if self.session.auth.remote_key is not None:
            logmessage.append(
                f"\tRemote-Publickey: {self.session.auth.remote_key.get_name()} {self.session.auth.remote_key.fingerprint} {self.session.auth.remote_key.get_bits()}bits"
            )

        ssh_keys = None
        if self.session.auth.agent:
            ssh_keys = get_agent_pubkeys()

        logmessage.append(
            f"\tAgent: {f'available keys: {len(ssh_keys or [])}' if ssh_keys else 'no agent'}"
        )
        if ssh_keys is not None:
            logmessage.append(
                "\n".join(
                    [
                        f"\t\tAgent-Key: {k.get_name()} {k.hash_sha256()} {k.get_bits()}bits, can sign: {k.can_sign()}"
                        for k in ssh_keys
                    ]
                )
            )

        logging.info("\n".join(logmessage))

    def on_session_close(self) -> None:
        pass


class AuthenticatorRemote(Authenticator):

    @classmethod
    def parser_arguments(cls) -> None:
        super().parser_arguments()
        cls.argument_group()

    def get_auth_methods(
        self, _host: str, _port: int, _username: str | None = None
    ) -> list[str] | None:
        return ["publickey"]

    def auth_agent(self, _username: str, _host: str, _port: int) -> int:
        return paramiko.common.AUTH_FAILED

    def auth_password(
        self, _username: str, _host: str, _port: int, _password: str
    ) -> int:
        return paramiko.common.AUTH_FAILED

    def auth_publickey(self, username: str, host: str, port: int, key: PKey) -> int:
        if key.can_sign():
            logging.debug(
                "AuthenticatorRemote.auth_publickey: username=%s, key=%s %s %sbits",
                username,
                key.get_name(),
                key.fingerprint,
                key.get_bits(),
            )
            return self.connect(
                username, host, port, AuthenticationMethod.PUBLICKEY, key=key
            )
        return paramiko.common.AUTH_FAILED
