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

    def valid(self, msg: paramiko.message.Message) -> None:  # type: ignore
        del msg  # unused arguments
        self.auth_event.set()
        self.authenticated = True

    def parse_service_accept(self, m: paramiko.message.Message) -> None:  # type: ignore
        # https://tools.ietf.org/html/rfc4252#section-7
        service = m.get_text()
        if not (service == "ssh-userauth" and self.auth_method == "publickey"):
            return self._parse_service_accept(m)  # type: ignore
        m = paramiko.message.Message()
        m.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
        m.add_string(self.username)
        m.add_string("ssh-connection")
        m.add_string(self.auth_method)
        m.add_boolean(False)
        if self.private_key.public_blob.key_type == 'ssh-rsa':
            m.add_string('rsa-sha2-512')
        else:
            m.add_string(self.private_key.public_blob.key_type)
        m.add_string(self.private_key.public_blob.key_blob)
        self.transport._send_message(m)

    valid_key = False
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
        client_handler_table[paramiko.common.MSG_USERAUTH_INFO_REQUEST] = \
            paramiko.auth_handler.AuthHandler._parse_userauth_info_request  # type: ignore
        client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = \
            paramiko.auth_handler.AuthHandler._parse_service_accept  # type: ignore
    return valid_key


class RemoteCredentials():

    def __init__(
        self, *,
        username: str,
        password: Optional[str] = None,
        key: Optional[PKey] = None,
        host: Optional[str] = None,
        port: Optional[int] = None
    ) -> None:
        self.username: str = username
        self.password: Optional[str] = password
        self.key: Optional[PKey] = key
        self.host: Optional[str] = host
        self.port: Optional[int] = port


class Authenticator(BaseModule):

    REQUEST_AGENT_BREAKIN = False

    @classmethod
    def parser_arguments(cls) -> None:
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
        super().__init__()
        self.session = session

    def get_remote_host_credentials(
        self,
        username: str,
        password: Optional[str] = None,
        key: Optional[PKey] = None
    ) -> RemoteCredentials:
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
        auth_methods = None
        t = paramiko.Transport((host, port))
        try:
            t.connect()
        except paramiko.ssh_exception.SSHException:
            t.close()
            return auth_methods
        try:
            t.auth_none('')
        except paramiko.BadAuthenticationType as err:
            auth_methods = err.allowed_types
        finally:
            t.close()
        return auth_methods

    def authenticate(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        key: Optional[PKey] = None,
        store_credentials: bool = True
    ) -> int:
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
        except Exception:
            logging.exception("internal error, abort authentication!")
        return paramiko.common.AUTH_FAILED

    def auth_agent(self, username: str, host: str, port: int) -> int:
        raise NotImplementedError("authentication must be implemented")

    def auth_password(self, username: str, host: str, port: int, password: str) -> int:
        raise NotImplementedError("authentication must be implemented")

    def auth_publickey(self, username: str, host: str, port: int, key: PKey) -> int:
        raise NotImplementedError("authentication must be implemented")

    def auth_fallback(self, username: str) -> int:
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
            method=AuthenticationMethod.password,
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
        pass

    def post_auth_action(self, success: bool) -> None:
        pass


class AuthenticatorPassThrough(Authenticator):
    """pass the authentication to the remote server (reuses the credentials)
    """

    def auth_agent(self, username: str, host: str, port: int) -> int:
        return self.connect(username, host, port, AuthenticationMethod.agent)

    def auth_password(self, username: str, host: str, port: int, password: str) -> int:
        return self.connect(username, host, port, AuthenticationMethod.password, password=password)

    def auth_publickey(self, username: str, host: str, port: int, key: PKey) -> int:
        ssh_pub_key = SSHKey(f"{key.get_name()} {key.get_base64()}")
        ssh_pub_key.parse()
        if key.can_sign():
            logging.debug(
                "AuthenticatorPassThrough.auth_publickey: username=%s, key=%s %s %sbits",
                username, key.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits
            )
            return self.connect(username, host, port, AuthenticationMethod.publickey, key=key)
        # Ein Publickey wird nur direkt von check_auth_publickey
        # übergeben. In dem Fall müssen wir den Client authentifizieren,
        # damit wir auf den Agent warten können!
        publickey = paramiko.pkey.PublicBlob(key.get_name(), key.asbytes())
        if probe_host(host, port, username, publickey):
            logging.debug((
                "Found valid key for host %s:%s username=%s, key=%s %s %sbits",
                host, port, username, key.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits
            ))
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def post_auth_action(self, success: bool) -> None:
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
