import logging
import os
from typing import (
    Any,
    List,
    Union,
    Tuple,
    Type,
    ByteString,
    Optional
)

import paramiko
from paramiko.pkey import PKey
from sshpubkeys import SSHKey  # type: ignore

import sshmitm
from sshmitm.moduleparser import BaseModule
from sshmitm.authentication import RemoteCredentials
from sshmitm.clients.sftp import SFTPClient
from sshmitm.forwarders.tunnel import TunnelForwarder, LocalPortForwardingForwarder, RemotePortForwardingForwarder


class BaseServerInterface(paramiko.ServerInterface, BaseModule):

    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super().__init__()
        self.session: 'sshmitm.session.Session' = session
        self.forwarders: List[Union[TunnelForwarder, LocalPortForwardingForwarder, RemotePortForwardingForwarder]] = []
        self.possible_auth_methods: Optional[List[str]] = None


class ServerInterface(BaseServerInterface):
    """ssh server implementation for SSH-MITM
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(
            cls.__name__,
            "options for integrated ssh server"
        )
        plugin_group.add_argument(
            '--disable-ssh',
            dest='disable_ssh',
            action='store_true',
            help='disable ssh'
        )
        plugin_group.add_argument(
            '--disable-scp',
            dest='disable_scp',
            action='store_true',
            help='disable scp'
        )
        plugin_group.add_argument(
            '--disable-password-auth',
            dest='disable_password_auth',
            action='store_true',
            help='disable password authentication'
        )
        plugin_group.add_argument(
            '--disable-publickey-auth',
            dest='disable_pubkey_auth',
            action='store_true',
            help='disable public key authentication (not RFC-4252 conform)'
        )
        plugin_group.add_argument(
            '--accept-first-publickey',
            dest='accept_first_publickey',
            action='store_true',
            help='accepts the first key - does not check if user is allowed to login with publickey authentication'
        )
        plugin_group.add_argument(
            '--disallow-publickey-auth',
            dest='disallow_publickey_auth',
            action='store_true',
            help='disallow public key authentication but still checks if publickey authentication would be possible'
        )
        plugin_group.add_argument(
            '--enable-none-auth',
            dest='enable_none_auth',
            action='store_true',
            help='enable "none" authentication'
        )
        plugin_group.add_argument(
            '--enable-trivial-auth',
            dest='enable_trivial_auth',
            action='store_true',
            help='enables "trivial success authentication" phishing attack'
        )
        plugin_group.add_argument(
            '--enable-keyboard-interactive-auth',
            dest='enable_keyboard_interactive_auth',
            action='store_true',
            help='enable "keyboard-interactive" authentication'
        )
        plugin_group.add_argument(
            '--disable-keyboard-interactive-prompts',
            dest='disable_keyboard_interactive_prompts',
            action='store_true',
            help='disable prompts for keyboard-interactive'
        )
        plugin_group.add_argument(
            '--extra-auth-methods',
            dest='extra_auth_methods',
            help='extra authentication mehtod names'
        )
        plugin_group.add_argument(
            '--disable-auth-method-lookup',
            dest='disable_auth_method_lookup',
            action='store_true',
            help='disable auth method lookup on remote server during authentication'
        )

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        logging.debug("check_channel_exec_request: channel=%s, command=%s", channel, command.decode('utf8'))
        if self.args.disable_scp:
            logging.warning('scp command not allowed!')
            return False
        if command.decode('utf8').startswith('scp'):
            logging.debug("got scp command: %s", command.decode('utf8'))
            self.session.scp_requested = True
            self.session.scp_command = command
            self.session.scp_channel = channel
            return True

        if not self.args.disable_ssh:
            # we can use the scp forwarder for command executions
            logging.info("got ssh command: %s", command.decode('utf8'))

            # check if client want's to execute mosh-server
            # disable the requested shell and the pty to prevent
            # intercepting the wrong shell
            if command.startswith(b"mosh-server"):
                self.session.ssh_requested = False
                self.session.ssh_pty_kwargs = None

            self.session.scp_requested = True
            self.session.scp_command = command
            self.session.scp_channel = channel
            return True
        logging.warning('ssh command not allowed!')
        return False

    def check_channel_forward_agent_request(self, channel: paramiko.Channel) -> bool:
        logging.debug("check_channel_forward_agent_request: channel=%s", channel)
        self.session.agent_requested.set()
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        logging.debug("check_channel_shell_request: channel=%s", channel)
        if not self.args.disable_ssh:
            self.session.ssh_requested = True
            self.session.ssh_channel = channel
            return True
        return False

    def check_channel_pty_request(
        self,
        channel: paramiko.channel.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes
    ) -> bool:
        logging.debug(
            "check_channel_pty_request: channel=%s, term=%s, width=%s, height=%s, pixelwidth=%s, pixelheight=%s, modes=%s",
            channel, term, width, height, pixelwidth, pixelheight, modes
        )
        if not self.args.disable_ssh:
            self.session.ssh_requested = True
            self.session.ssh_pty_kwargs = {
                'term': term,
                'width': width,
                'height': height,
                'width_pixels': pixelwidth,
                'height_pixels': pixelheight
            }
            return True
        return False

    def get_allowed_auths(self, username: str) -> str:
        if self.possible_auth_methods is None and not self.args.disable_auth_method_lookup:
            creds: RemoteCredentials = self.session.authenticator.get_remote_host_credentials(username)
            if creds.host is not None and creds.port is not None:
                try:
                    self.possible_auth_methods = self.session.authenticator.get_auth_methods(creds.host, creds.port)
                    logging.info(
                        "Remote auth-methods: %s",
                        str(self.possible_auth_methods)
                    )
                except paramiko.ssh_exception.SSHException as ex:
                    self.session.remote_address_reachable = False
                    logging.error(ex)
                    return 'publickey'
        logging.debug("get_allowed_auths: username=%s", username)
        allowed_auths = []
        if self.args.extra_auth_methods:
            allowed_auths.extend(self.args.extra_auth_methods.split(','))
        if self.args.enable_keyboard_interactive_auth or self.args.enable_trivial_auth:
            allowed_auths.append('keyboard-interactive')
        if not self.args.disable_pubkey_auth:
            allowed_auths.append('publickey')
        if not self.args.disable_password_auth:
            allowed_auths.append('password')
        if allowed_auths or self.args.enable_none_auth:
            allowed_authentication_methods = ','.join(allowed_auths)
            logging.debug("Allowed authentication methods: %s", allowed_authentication_methods)
            return allowed_authentication_methods
        logging.warning('Authentication is set to "none", but logins are disabled!')
        return 'none'

    def check_auth_none(self, username: str) -> int:
        logging.debug("check_auth_none: username=%s", username)
        if self.args.enable_none_auth:
            self.session.authenticator.authenticate(username, key=None)
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: Union[bytes, str]
    ) -> Union[int, paramiko.server.InteractiveQuery]:
        logging.debug("check_auth_interactive: username=%s, submethods=%s", username, submethods)
        is_trivial_auth = self.args.enable_trivial_auth and self.session.accepted_key is not None
        logging.debug("trivial authentication possible")
        if not self.args.enable_keyboard_interactive_auth and not is_trivial_auth:
            return paramiko.common.AUTH_FAILED
        self.session.username = username
        auth_interactive_query = paramiko.server.InteractiveQuery()
        if not self.args.disable_keyboard_interactive_prompts and not is_trivial_auth:
            auth_interactive_query.add_prompt("Password (kb-interactive): ", False)
        return auth_interactive_query

    def check_auth_interactive_response(self, responses: List[str]) -> Union[int, paramiko.server.InteractiveQuery]:
        logging.debug("check_auth_interactive_response: responses=%s", responses)
        is_trivial_auth = self.args.enable_trivial_auth and self.session.accepted_key is not None
        if self.args.disable_keyboard_interactive_prompts or is_trivial_auth:
            self.session.authenticator.authenticate(self.session.username, key=None)
            return paramiko.common.AUTH_SUCCESSFUL
        if not responses:
            return paramiko.common.AUTH_FAILED
        return self.session.authenticator.authenticate(self.session.username, password=responses[0])

    def check_auth_publickey(self, username: str, key: PKey) -> int:
        ssh_pub_key = SSHKey(f"{key.get_name()} {key.get_base64()}")
        ssh_pub_key.parse()
        logging.debug(
            "check_auth_publickey: username=%s, key=%s %s %sbits",
            username, key.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits
        )

        if self.session.session_log_dir:
            os.makedirs(self.session.session_log_dir, exist_ok=True)
            pubkeyfile_path = os.path.join(self.session.session_log_dir, 'publickeys')
            with open(pubkeyfile_path, 'a+', encoding="utf-8") as pubkeyfile:
                pubkeyfile.write(f"{key.get_name()} {key.get_base64()} saved-from-auth-publickey\n")
        if self.args.disable_pubkey_auth:
            logging.debug("Publickey login attempt, but publickey auth was disabled!")
            return paramiko.common.AUTH_FAILED
        if self.args.accept_first_publickey:
            logging.debug('host probing disabled - first key accepted')
            if self.args.disallow_publickey_auth:
                logging.debug('ignoring argument --disallow-publickey-auth, first key still accepted')
            self.session.authenticator.authenticate(username, key=None)
            self.session.accepted_key = key
            return paramiko.common.AUTH_SUCCESSFUL
        if not self.session.remote_address_reachable:
            return paramiko.common.AUTH_FAILED

        auth_result: int = self.session.authenticator.authenticate(username, key=key)
        if auth_result == paramiko.common.AUTH_SUCCESSFUL:
            self.session.accepted_key = key
        if self.session.accepted_key is not None and self.args.enable_trivial_auth:
            logging.debug("found valid key for trivial authentication")
            return paramiko.common.AUTH_FAILED
        if self.args.disallow_publickey_auth:
            return paramiko.common.AUTH_FAILED
        return auth_result

    def check_auth_password(self, username: str, password: str) -> int:
        logging.debug("check_auth_password: username=%s, password=%s", username, password)
        if self.args.disable_password_auth:
            logging.warning("Password login attempt, but password auth was disabled!")
            return paramiko.common.AUTH_FAILED
        if not self.session.remote_address_reachable:
            return paramiko.common.AUTH_FAILED
        return self.session.authenticator.authenticate(username, password=password)

    def check_channel_request(self, kind: str, chanid: int) -> int:
        logging.debug("check_channel_request: kind=%s , chanid=%s", kind, chanid)
        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_env_request(self, channel: paramiko.Channel, name: bytes, value: bytes) -> bool:
        logging.debug("check_channel_env_request: channel=%s, name=%s, value=%s", channel, name, value)
        self.session.env_requests[name] = value
        return True

    def check_channel_subsystem_request(self, channel: paramiko.Channel, name: str) -> bool:
        logging.debug("check_channel_subsystem_request: channel=%s, name=%s", channel, name)
        if name.lower() == 'sftp':
            self.session.sftp_requested = True
            self.session.sftp_channel = channel
        return super().check_channel_subsystem_request(channel, name)

    def check_port_forward_request(self, address: str, port: int) -> int:
        """
        Note that the if the client requested the port, we must handle it or
        return false.
        Only if it requested 0 as port we can open a random port (actually the
        OS will tell us which port).
        If it can't be opened, we just return false.
        """
        logging.debug(
            "check_port_forward_request: address=%s, port=%s",
            address, port
        )
        if self.session.ssh_client is None:
            logging.debug("check_port_forward_request: session.ssh_client is None")
            return False
        if self.session.ssh_client.transport is None:
            logging.debug("check_port_forward_request: session.ssh_client.transport is None")
            return False
        try:
            return self.session.ssh_client.transport.request_port_forward(
                address,
                port,
                self.session.proxyserver.server_tunnel_interface(self.session, self, (address, port)).handler
            )
        except paramiko.ssh_exception.SSHException:
            logging.info("TCP forwarding request denied")
            return False

    def cancel_port_forward_request(self, address: str, port: int) -> None:
        logging.info(
            "cancel_port_forward_request: address=%s, port=%s",
            address, port
        )
        username = self.session.transport.get_username()
        logging.info(
            "Cancel port forward request on %s:%i by %s.", address,
            port, username, extra={'username': username}
        )
        if self.session.ssh_client is None:
            logging.debug("cancel_port_forward_request: session.ssh_client is None!")
            return
        if self.session.ssh_client.transport is None:
            logging.debug("cancel_port_forward_request: session.ssh_client.transport is None!")
            return
        self.session.ssh_client.transport.cancel_port_forward(address, port)

    def check_channel_direct_tcpip_request(self, chanid: int, origin: Tuple[str, int], destination: Tuple[str, int]) -> int:
        username = self.session.transport.get_username()
        logging.info(
            "channel_direct_tcpip_request: chanid=%s, origin=%s, destination=%s, username=%s",
            chanid, origin, destination, username
        )

        try:
            tunnel_forwarder = self.session.proxyserver.client_tunnel_interface(self.session, chanid, origin, destination)
            self.forwarders.append(tunnel_forwarder)
        except paramiko.ssh_exception.ChannelException:
            logging.error("Could not setup forward from %s to %s.", origin, destination)
            return paramiko.common.OPEN_FAILED_CONNECT_FAILED

        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_window_change_request(
        self, channel: paramiko.Channel, width: int, height: int, pixelwidth: int, pixelheight: int
    ) -> bool:
        logging.debug(
            "check_channel_window_change_request: channel=%s, width=%s, height=%s, pixelwidth=%s, pixelheight=%s",
            channel, width, height, pixelwidth, pixelheight
        )
        if self.session.ssh_channel:
            self.session.ssh_channel.resize_pty(width, height, pixelwidth, pixelheight)
            return True
        return False

    def check_channel_x11_request(
        self, channel: paramiko.Channel, single_connection: bool,
        auth_protocol: str, auth_cookie: ByteString, screen_number: int
    ) -> bool:
        logging.debug(
            "check_channel_x11_request: channel=%s, single_connection=%s, auth_protocol=%s, auth_cookie=%s, screen_number=%s",
            channel, single_connection, auth_protocol, auth_cookie, screen_number
        )
        return False

    def check_global_request(
        self, kind: str, msg: paramiko.message.Message
    ) -> Union[bool, Tuple[Union[bool, int, str], ...]]:
        logging.debug(
            "check_global_request: kind=%s, msg=%s", kind, msg
        )
        return False


class ProxySFTPServer(paramiko.SFTPServer):

    def __init__(
        self,
        channel: paramiko.Channel,
        name: str,
        server: ServerInterface,
        sftp_si: Type[paramiko.SFTPServerInterface],
        session: 'sshmitm.session.Session',
        *largs: Any,
        **kwargs: Any
    ) -> None:
        super().__init__(channel, name, server, sftp_si, *largs, **kwargs)
        self.session = session

    def start_subsystem(
        self, name: str, transport: paramiko.Transport, channel: paramiko.Channel
    ) -> None:
        self.session.sftp_client = SFTPClient.from_client(self.session.ssh_client)
        if not self.session.sftp_client:
            return
        self.session.sftp_client.subsystem_count += 1
        super().start_subsystem(name, transport, channel)

    def finish_subsystem(self) -> None:
        super().finish_subsystem()
        if not self.session.sftp_client:
            return
        self.session.sftp_client.subsystem_count -= 1
        self.session.sftp_client.close()
