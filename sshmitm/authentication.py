import logging
import os
import sys
import socket

from typing import (
    Optional,
    List,
    Tuple
)

from colored.colored import stylize, attr, fg  # type: ignore
from paramiko import PKey
from rich._emoji_codes import EMOJI

import paramiko
from sshpubkeys import SSHKey  # type: ignore

import sshmitm
from sshmitm.moduleparser import BaseModule
from sshmitm.clients.ssh import SSHClient, AuthenticationMethod
from sshmitm.exceptions import MissingHostException


def probe_host(hostname_or_ip: str, port: int, username: str, public_key: paramiko.pkey.PublicBlob) -> bool:
    """
    Probe a remote host to determine if the provided public key is authorized for the provided username.

    The function takes four arguments: hostname_or_ip (a string representing hostname
    or IP address), port (an integer representing the port number), username (a string
    representing the username), and public_key (a public key in paramiko.pkey.PublicBlob format).
    The function returns a boolean indicating if the provided public key is authorized or not.

    The function uses the paramiko library to perform the probe by creating a secure shell (SSH)
    connection to the remote host and performing authentication using the provided username and
    public key. Two helper functions, valid and parse_service_accept, are defined inside the
    probe_host function to assist with the authentication process.

    The probe_host function opens a socket connection to the remote host and starts an
    SSH transport using the paramiko library. The function then generates a random private
    key, replaces the public key with the provided key, and performs the public key
     using transport.auth_publickey. The result of the authentication is stored in the
     valid_key variable. If the authentication fails, an exception of type
     paramiko.ssh_exception.AuthenticationException is raised and caught, leaving the
     valid_key variable as False. Finally, the function returns the value of valid_key,
     which indicates whether the provided public key is authorized or not.

    :param hostname_or_ip: Hostname or IP address of the remote host to probe.
    :type hostname: str
    :param port: Port of the remote host.
    :type port: int
    :param username: The username to probe authorization for.
    :type username: str
    :param public_key: The public key to use for the probe.
    :type public_key: paramiko.pkey.PublicBlob

    :returns: True if the provided public key is authorized, False otherwise.
    :rtype: bool
    """
    # pylint: disable=protected-access
    def valid(self, msg: paramiko.message.Message) -> None:  # type: ignore
        """
        A helper function that is called when authentication is successful.

        Args:
            msg (paramiko.message.Message): The message that was sent.
        """
        del msg  # unused arguments
        self.auth_event.set()
        self.authenticated = True

    def parse_service_accept(self, message: paramiko.message.Message) -> None:  # type: ignore
        """
        A helper function that parses the service accept message.

        Args:
            message (paramiko.message.Message): The message to parse.
        """
        # https://tools.ietf.org/html/rfc4252#section-7
        service = message.get_text()
        if not (service == "ssh-userauth" and self.auth_method == "publickey"):
            return self._parse_service_accept(message)  # type: ignore
        message = paramiko.message.Message()
        message.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
        message.add_string(self.username)
        message.add_string("ssh-connection")
        message.add_string(self.auth_method)
        message.add_boolean(False)
        if self.private_key.public_blob.key_type == 'ssh-rsa':
            message.add_string('rsa-sha2-512')
        else:
            message.add_string(self.private_key.public_blob.key_type)
        message.add_string(self.private_key.public_blob.key_blob)
        self.transport._send_message(message)
        return None

    valid_key = False
    sock = None
    transport = None
    try:
        client_handler_table = paramiko.auth_handler.AuthHandler._client_handler_table  # type: ignore
        client_handler_table[paramiko.common.MSG_USERAUTH_INFO_REQUEST] = valid
        client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = parse_service_accept

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname_or_ip, port))
        transport = paramiko.transport.Transport(sock)
        transport.start_client()

        # For compatibility with paramiko, we need to generate a random private key and replace
        # the public key with our data.
        key: PKey = paramiko.RSAKey.generate(2048)
        key.public_blob = public_key
        transport.auth_publickey(username, key)
        valid_key = True
    except paramiko.ssh_exception.AuthenticationException:
        pass
    finally:
        if transport is not None:
            transport.close()
        if sock is not None:
            sock.close()
        client_handler_table[paramiko.common.MSG_USERAUTH_INFO_REQUEST] = \
            paramiko.auth_handler.AuthHandler._parse_userauth_info_request  # type: ignore
        client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = \
            paramiko.auth_handler.AuthHandler._parse_service_accept  # type: ignore
    return valid_key


class RemoteCredentials:
    """
    The `RemoteCredentials` class represents the credentials required to access a remote host.
    """

    def __init__(
        self, *,
        username: str,
        password: Optional[str] = None,
        key: Optional[PKey] = None,
        host: Optional[str] = None,
        port: Optional[int] = None
    ) -> None:
        """
        The `__init__` method is the constructor of the class and it is used to initialize the attributes of the class.

        :param username: (str) a string representing the username of the remote host. This is a required argument and must be specified when creating an instance of the class.
        :param password: (str) an optional string representing the password of the remote host. This argument is optional and if not specified, the value will be `None`.
        :param key: (PKey) an optional `PKey` object representing a private key used to authenticate with the remote host. This argument is optional and if not specified, the value will be `None`.
        :param host: (str) an optional string representing the hostname or IP address of the remote host. This argument is optional and if not specified, the value will be `None`.
        :param port: (int) an optional integer representing the port number used to connect to the remote host. This argument is optional and if not specified, the value will be `None`.
        :return: None
        """
        self.username: str = username
        """
        (str) a string representing the username of the remote host.
        """

        self.password: Optional[str] = password
        """
        (str) an optional string representing the password of the remote host. This argument is optional and if not specified, the value will be `None`.
        """

        self.key: Optional[PKey] = key
        """
        (PKey) an optional `PKey` object representing a private key used to authenticate with the remote host. This argument is optional and if not specified, the value will be `None`.
        """

        self.host: Optional[str] = host
        """
        (str) an optional string representing the hostname or IP address of the remote host. This argument is optional and if not specified, the value will be `None`.
        """

        self.port: Optional[int] = port
        """
        (int) an optional integer representing the port number used to connect to the remote host. This argument is optional and if not specified, the value will be `None`.
        """


class Authenticator(BaseModule):

    REQUEST_AGENT_BREAKIN = False
    """
    This flag indicates if SSH-MITM should do a breakin to the client's ssh agent, even in cases where the agent is not forwarded.

    :param session: an object of sshmitm.session.Session class to store session information.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        """
        Adds the options for remote authentication using argparse.

        :return: None
        """
        plugin_group = cls.parser().add_argument_group(
            cls.__name__,
            "options for remote authentication"
        )
        plugin_group.add_argument(
            '--remote-host',
            dest='remote_host',
            help='remote host to connect to (default 127.0.0.1)'
        )
        plugin_group.add_argument(
            '--remote-port',
            type=int,
            dest='remote_port',
            help='remote port to connect to (default 22)'
        )
        plugin_group.add_argument(
            '--auth-username',
            dest='auth_username',
            help='username for remote authentication'
        )
        plugin_group.add_argument(
            '--auth-password',
            dest='auth_password',
            help='password for remote authentication'
        )

        plugin_group.add_argument(
            '--hide-credentials',
            dest='auth_hide_credentials',
            action='store_true',
            help='do not log credentials (usefull for presentations)'
        )

        honeypot_group = cls.parser().add_argument_group(
            "AuthenticationFallback"
        )
        honeypot_group.add_argument(
            '--enable-auth-fallback',
            action='store_true',
            default=False,
            help="use a honeypot if no agent was forwarded to login with publickey auth "
        )
        honeypot_group.add_argument(
            '--fallback-host',
            dest='fallback_host',
            required='--enable-auth-fallback' in sys.argv,
            help='fallback host for the honeypot'
        )
        honeypot_group.add_argument(
            '--fallback-port',
            dest='fallback_port',
            type=int,
            default=22,
            help='fallback port for the honeypot'
        )
        honeypot_group.add_argument(
            '--fallback-username',
            dest='fallback_username',
            required='--enable-auth-fallback' in sys.argv,
            help='username for the honeypot'
        )
        honeypot_group.add_argument(
            '--fallback-password',
            dest='fallback_password',
            required='--enable-auth-fallback' in sys.argv,
            help='password for the honeypot'
        )

    def __init__(self, session: 'sshmitm.session.Session') -> None:
        """
        Initializes Authenticator instance.
        """
        super().__init__()
        self.session = session

    def get_remote_host_credentials(
        self,
        username: str,
        password: Optional[str] = None,
        key: Optional[PKey] = None
    ) -> RemoteCredentials:
        """
        Get the credentials for remote host.

        :param username: remote host username.
        :param password: remote host password.
        :param key: remote host private key.
        :return: an object of RemoteCredentials class.
        """
        if self.session.proxyserver.transparent:
            return RemoteCredentials(
                username=self.args.auth_username or username,
                password=self.args.auth_password or password,
                key=key,
                host=self.args.remote_host or self.session.socket_remote_address[0],
                port=self.args.remote_port or self.session.socket_remote_address[1]
            )
        return RemoteCredentials(
            username=self.args.auth_username or username,
            password=self.args.auth_password or password,
            key=key,
            host=self.args.remote_host or '127.0.0.1',
            port=self.args.remote_port or 22
        )

    @classmethod
    def get_auth_methods(cls, host: str, port: int) -> Optional[List[str]]:
        """
        Get the available authentication methods for a remote host.

        :param host: remote host address.
        :param port: remote host port.
        :return: a list of strings representing the available authentication methods.
        """
        auth_methods = None
        remote_transport = paramiko.Transport((host, port))
        try:
            remote_transport.connect()
        except paramiko.ssh_exception.SSHException:
            remote_transport.close()
            return auth_methods
        try:
            remote_transport.auth_none('')
        except paramiko.BadAuthenticationType as err:
            auth_methods = err.allowed_types
        finally:
            remote_transport.close()
        return auth_methods

    def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key: Optional[PKey] = None,
        store_credentials: bool = True
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
            self.session.username_provided = username
            self.session.password_provided = password
        if username:
            remote_credentials: RemoteCredentials = self.get_remote_host_credentials(username, password, key)
            self.session.username = remote_credentials.username
            self.session.password = remote_credentials.password
            self.session.remote_key = remote_credentials.key
            self.session.remote_address = (remote_credentials.host, remote_credentials.port)
        if key and not self.session.remote_key:
            self.session.remote_key = key

        if self.session.remote_address[0] is None or self.session.remote_address[1] is None:
            logging.error("no remote host")
            return paramiko.common.AUTH_FAILED

        try:
            if self.session.agent:
                return self.auth_agent(
                    self.session.username,
                    self.session.remote_address[0],
                    self.session.remote_address[1]
                )
            if self.session.password:
                return self.auth_password(
                    self.session.username,
                    self.session.remote_address[0],
                    self.session.remote_address[1],
                    self.session.password
                )
            if self.session.remote_key:
                return self.auth_publickey(
                    self.session.username,
                    self.session.remote_address[0],
                    self.session.remote_address[1],
                    self.session.remote_key
                )
        except MissingHostException:
            logging.error("no remote host")
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("internal error, abort authentication!")
        return paramiko.common.AUTH_FAILED

    def auth_agent(self, username: str, host: str, port: int) -> int:
        """
        Performs authentication using the ssh-agent.
        """
        raise NotImplementedError("authentication must be implemented")

    def auth_password(self, username: str, host: str, port: int, password: str) -> int:
        """
        Performs authentication using a password.
        """
        raise NotImplementedError("authentication must be implemented")

    def auth_publickey(self, username: str, host: str, port: int, key: PKey) -> int:
        """
        Performs authentication using public key authentication.
        """
        raise NotImplementedError("authentication must be implemented")

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
            if self.session.agent:
                logging.error("\n".join([
                    stylize(
                        EMOJI['exclamation'] +
                        " ssh agent keys are not allowed for signing. Remote authentication not possible.",
                        fg('red') + attr('bold')
                    ),
                    stylize(
                        EMOJI['information'] +
                        " To intercept clients, you can provide credentials for a honeypot.",
                        fg('yellow') + attr('bold')
                    )
                ]))
            else:
                logging.error("\n".join([
                    stylize(
                        EMOJI['exclamation'] +
                        " ssh agent not forwarded. Login to remote host not possible with publickey authentication.",
                        fg('red') + attr('bold')
                    ),
                    stylize(
                        EMOJI['information'] +
                        " To intercept clients without a forwarded agent, you can provide credentials for a honeypot.",
                        fg('yellow') + attr('bold')
                    )
                ]))
            return paramiko.common.AUTH_FAILED

        auth_status = self.connect(
            user=self.args.fallback_username or username,
            password=self.args.fallback_password,
            host=self.args.fallback_host,
            port=self.args.fallback_port,
            method=AuthenticationMethod.PASSWORD,
            run_post_auth=False
        )
        if auth_status == paramiko.common.AUTH_SUCCESSFUL:
            logging.warning(
                stylize(
                    EMOJI['warning'] + " publickey authentication failed - no agent forwarded - connecting to honeypot!",
                    fg('yellow') + attr('bold')
                ),
            )
        else:
            logging.error(
                stylize(EMOJI['exclamation'] + " Authentication against honeypot failed!", fg('red') + attr('bold')),
            )
        return auth_status

    def connect(
        self, user: str, host: str, port: int, method: AuthenticationMethod,
        password: Optional[str] = None, key: Optional[PKey] = None, *, run_post_auth: bool = True
    ) -> int:
        """
        Connects to the SSH server and performs the necessary authentication.
        """
        if not host:
            raise MissingHostException()

        auth_status = paramiko.common.AUTH_FAILED
        self.session.ssh_client = SSHClient(
            host,
            port,
            method,
            password,
            user,
            key,
            self.session
        )
        self.pre_auth_action()
        try:
            if self.session.ssh_client is not None and self.session.ssh_client.connect():
                auth_status = paramiko.common.AUTH_SUCCESSFUL
        except paramiko.SSHException:
            logging.error(stylize("Connection to remote server refused", fg('red') + attr('bold')))
            return paramiko.common.AUTH_FAILED
        if run_post_auth:
            self.post_auth_action(auth_status == paramiko.common.AUTH_SUCCESSFUL)
        return auth_status

    def pre_auth_action(self) -> None:
        """Perform any pre-authentication actions.

        This method is called before the authentication process starts.

        :return: None
        """

    def post_auth_action(self, success: bool) -> None:
        """Perform any post-authentication actions.

        This method is called after the authentication process is completed, whether successfully or not.

        :param success: indicates if the authentication was successful or not
        :return: None
        """


class AuthenticatorPassThrough(Authenticator):
    """A subclass of `Authenticator` which passes the authentication to the remote server.

    This class reuses the credentials received from the client and sends it directly to the remote server for authentication.
    """

    def auth_agent(self, username: str, host: str, port: int) -> int:
        return self.connect(username, host, port, AuthenticationMethod.AGENT)

    def auth_password(self, username: str, host: str, port: int, password: str) -> int:
        return self.connect(username, host, port, AuthenticationMethod.PASSWORD, password=password)

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
        ssh_pub_key = SSHKey(f"{key.get_name()} {key.get_base64()}")
        ssh_pub_key.parse()
        if key.can_sign():
            logging.debug(
                "AuthenticatorPassThrough.auth_publickey: username=%s, key=%s %s %sbits",
                username, key.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits
            )
            return self.connect(username, host, port, AuthenticationMethod.PUBLICKEY, key=key)
        # A public key is only passed directly from check_auth_publickey.
        # In that case, we need to authenticate the client so that we can wait for the agent!
        publickey = paramiko.pkey.PublicBlob(key.get_name(), key.asbytes())
        try:
            if probe_host(host, port, username, publickey):
                logging.debug((
                    "Found valid key for host %s:%s username=%s, key=%s %s %sbits",
                    host, port, username, key.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits
                ))
                return paramiko.common.AUTH_SUCCESSFUL
        except EOFError:
            logging.exception(
                "%s - faild to check if client is allowed to login with publickey authentication",
                self.session.sessionid
            )
        return paramiko.common.AUTH_FAILED

    def post_auth_action(self, success: bool) -> None:
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
        def get_agent_pubkeys() -> List[Tuple[str, SSHKey, bool, str]]:
            pubkeyfile_path = None

            keys_parsed: List[Tuple[str, SSHKey, bool, str]] = []
            if self.session.agent is None:
                return keys_parsed

            keys = self.session.agent.get_keys()
            for k in keys:
                ssh_pub_key = SSHKey(f"{k.get_name()} {k.get_base64()}")
                ssh_pub_key.parse()
                keys_parsed.append((k.get_name(), ssh_pub_key, k.can_sign(), k.get_base64()))

            if self.session.session_log_dir:
                os.makedirs(self.session.session_log_dir, exist_ok=True)
                pubkeyfile_path = os.path.join(self.session.session_log_dir, 'publickeys')
                with open(pubkeyfile_path, 'a+', encoding="utf-8") as pubkeyfile:
                    pubkeyfile.write("".join([
                        f"{k[0]} {k[3]} saved-from-agent\n"
                        for k in keys_parsed
                    ]))

            return keys_parsed

        logmessage = []
        if success:
            logmessage.append(stylize("Remote authentication succeeded", fg('green') + attr('bold')))
        else:
            logmessage.append(stylize("Remote authentication failed", fg('red')))

        if self.session.ssh_client is not None:
            logmessage.append(f"\tRemote Address: {self.session.ssh_client.host}:{self.session.ssh_client.port}")
            logmessage.append(f"\tUsername: {self.session.username_provided}")

        if self.session.password_provided:
            display_password = None
            if not self.args.auth_hide_credentials:
                display_password = self.session.password_provided
            logmessage.append(f"\tPassword: {display_password or stylize('*******', fg('dark_gray'))}")

        if self.session.accepted_key is not None and self.session.remote_key != self.session.accepted_key:
            ssh_pub_key = SSHKey(f"{self.session.accepted_key.get_name()} {self.session.accepted_key.get_base64()}")
            ssh_pub_key.parse()
            logmessage.append((
                "\tAccepted-Publickey: "
                f"{self.session.accepted_key.get_name()} {ssh_pub_key.hash_sha256()} {ssh_pub_key.bits}bits"
            ))

        if self.session.remote_key is not None:
            ssh_pub_key = SSHKey(f"{self.session.remote_key.get_name()} {self.session.remote_key.get_base64()}")
            ssh_pub_key.parse()
            logmessage.append(
                f"\tRemote-Publickey: {self.session.remote_key.get_name()} {ssh_pub_key.hash_sha256()} {ssh_pub_key.bits}bits"
            )

        ssh_keys = None
        if self.session.agent:
            ssh_keys = get_agent_pubkeys()

        logmessage.append(f"\tAgent: {f'available keys: {len(ssh_keys or [])}' if ssh_keys else 'no agent'}")
        if ssh_keys is not None:
            logmessage.append("\n".join(
                [f"\t\tAgent-Key: {k[0]} {k[1].hash_sha256()} {k[1].bits}bits, can sign: {k[2]}" for k in ssh_keys]
            ))

        logging.info("\n".join(logmessage))
