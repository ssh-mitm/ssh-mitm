import inspect
import logging
import os
import struct
from typing import TYPE_CHECKING, Any, List, Optional, Tuple, Type, Union

import paramiko
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.sftp import _VERSION, CMD_INIT, CMD_VERSION, SFTPError

from sshmitm.core.clients.sftp import SFTPClient
from sshmitm.moduleparser import BaseModule

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.core.authentication import RemoteCredentials
    from sshmitm.core.forwarders.tunnel import (
        LocalPortForwardingForwarder,
        RemotePortForwardingForwarder,
        TunnelForwarder,
    )


class BaseServerInterface(paramiko.ServerInterface, BaseModule):
    def __init__(self, session: "sshmitm.core.session.Session") -> None:
        super().__init__()
        self.session: "sshmitm.core.session.Session" = session
        self.session.register_session_thread()
        self.forwarders: List[
            Union[
                TunnelForwarder,
                LocalPortForwardingForwarder,
                RemotePortForwardingForwarder,
            ]
        ] = []
        self.possible_auth_methods: Optional[List[str]] = None


class ServerInterface(BaseServerInterface):
    """SSH-MITM server implementation"""

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--disable-ssh",
            dest="disable_ssh",
            action="store_true",
            help="Disables SSH functionality, preventing SSH connections to the server.",
        )
        plugin_group.add_argument(
            "--disable-scp",
            dest="disable_scp",
            action="store_true",
            help="Disables SCP (Secure Copy Protocol) functionality, preventing file transfers via SCP.",
        )
        plugin_group.add_argument(
            "--disable-password-auth",
            dest="disable_password_auth",
            action="store_true",
            help="Disables password-based authentication, forcing clients to use alternative authentication methods.",
        )
        plugin_group.add_argument(
            "--disable-publickey-auth",
            dest="disable_pubkey_auth",
            action="store_true",
            help="Disables public key authentication. Note that this is not RFC-4252 compliant.",
        )
        plugin_group.add_argument(
            "--accept-first-publickey",
            dest="accept_first_publickey",
            action="store_true",
            help="Accepts the first public key provided by the client without checking if the user is allowed to log in using public key authentication.",
        )
        plugin_group.add_argument(
            "--disallow-publickey-auth",
            dest="disallow_publickey_auth",
            action="store_true",
            help="Disallows public key authentication but still verifies whether public key authentication would be possible.",
        )
        plugin_group.add_argument(
            "--enable-none-auth",
            dest="enable_none_auth",
            action="store_true",
            help='Enables "none" authentication, which allows connections without any authentication.',
        )
        plugin_group.add_argument(
            "--enable-trivial-auth",
            dest="enable_trivial_auth",
            action="store_true",
            help='Enables "trivial success authentication" phishing attack, which simulates a successful authentication without actual validation.',
        )
        plugin_group.add_argument(
            "--enable-keyboard-interactive-auth",
            dest="enable_keyboard_interactive_auth",
            action="store_true",
            help='Enables "keyboard-interactive" authentication, allowing interactive authentication prompts.',
        )
        plugin_group.add_argument(
            "--disable-keyboard-interactive-prompts",
            dest="disable_keyboard_interactive_prompts",
            action="store_true",
            help="Disables prompts for keyboard-interactive authentication, preventing interactive authentication challenges.",
        )
        plugin_group.add_argument(
            "--extra-auth-methods",
            dest="extra_auth_methods",
            help="Specifies additional authentication method names that are supported by the server.",
        )
        plugin_group.add_argument(
            "--disable-auth-method-lookup",
            dest="disable_auth_method_lookup",
            action="store_true",
            help="Disables the lookup of supported authentication methods on the remote server during the authentication process.",
        )

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: bytes
    ) -> bool:
        logging.debug(
            "check_channel_exec_request: channel=%s, command=%s",
            channel,
            command.decode("utf8"),
        )
        if self.args.disable_scp:
            logging.warning("scp command not allowed!")
            return False
        if command.decode("utf8").startswith("scp"):
            logging.debug("got scp command: %s", command.decode("utf8"))
            self.session.register_interface(
                name="scp",
                interface=self.session.proxyserver.scp_interface,
                client_channel=channel,
                scp_command=command,
            )
            return True

        if not self.args.disable_ssh:
            # we can use the scp forwarder for command executions
            logging.info("got ssh command: %s", command.decode("utf8"))

            # check if client want's to execute mosh-server
            # disable the requested shell and the pty to prevent
            # intercepting the wrong shell
            if command.startswith(b"mosh-server"):
                self.session.ssh_pty_kwargs = None

            self.session.register_interface(
                name="scp",
                interface=self.session.proxyserver.scp_interface,
                client_channel=channel,
                scp_command=command,
            )
            return True
        logging.warning("ssh command not allowed!")
        return False

    def check_channel_forward_agent_request(self, channel: paramiko.Channel) -> bool:
        logging.debug("check_channel_forward_agent_request: channel=%s", channel)
        self.session.authenticator.agent_requested.set()
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        logging.debug("check_channel_shell_request: channel=%s", channel)
        if not self.args.disable_ssh:
            self.session.register_interface(
                name="ssh",
                interface=self.session.proxyserver.ssh_interface,
                client_channel=channel,
            )
            return True
        return False

    def check_channel_pty_request(  # pylint: disable=too-many-arguments
        self,
        channel: paramiko.channel.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        logging.debug(
            "check_channel_pty_request: channel=%s, term=%s, width=%s, height=%s, pixelwidth=%s, pixelheight=%s, modes=%s",
            channel,
            term,
            width,
            height,
            pixelwidth,
            pixelheight,
            modes,
        )
        if not self.args.disable_ssh:
            self.session.ssh_pty_kwargs = {
                "term": term,
                "width": width,
                "height": height,
                "width_pixels": pixelwidth,
                "height_pixels": pixelheight,
            }
            return True
        return False

    def get_allowed_auths(self, username: str) -> str:
        logging.debug("get_allowed_auths: username=%s", username)
        if (
            self.possible_auth_methods is None
            and not self.args.disable_auth_method_lookup
        ):
            creds: RemoteCredentials = (
                self.session.authenticator.get_remote_host_credentials(username)
            )
            if creds.host is not None and creds.port is not None:
                try:
                    self.possible_auth_methods = (
                        self.session.authenticator.get_auth_methods(
                            creds.host, creds.port, username
                        )
                    )
                    logging.info(
                        "Remote auth-methods: %s", str(self.possible_auth_methods)
                    )
                except paramiko.ssh_exception.SSHException as ex:
                    self.session.remote_address_reachable = False
                    logging.error(ex)
                    return "publickey"
        allowed_auths = []
        if self.args.extra_auth_methods:
            allowed_auths.extend(self.args.extra_auth_methods.split(","))
        if self.args.enable_keyboard_interactive_auth or self.args.enable_trivial_auth:
            allowed_auths.append("keyboard-interactive")
        if not self.args.disable_pubkey_auth:
            allowed_auths.append("publickey")
        if not self.args.disable_password_auth:
            allowed_auths.append("password")
        if allowed_auths or self.args.enable_none_auth:
            allowed_authentication_methods = ",".join(allowed_auths)
            logging.debug(
                "Allowed authentication methods: %s", allowed_authentication_methods
            )
            return allowed_authentication_methods
        logging.warning('Authentication is set to "none", but logins are disabled!')
        return "none"

    def check_auth_none(self, username: str) -> int:
        logging.debug("check_auth_none: username=%s", username)
        if self.args.enable_none_auth:
            self.session.authenticator.authenticate(username, key=None)
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: Union[bytes, str]
    ) -> Union[int, paramiko.server.InteractiveQuery]:
        logging.debug(
            "check_auth_interactive: username=%s, submethods=%s", username, submethods
        )
        is_trivial_auth = (
            self.args.enable_trivial_auth and self.session.accepted_key is not None
        )
        logging.debug("trivial authentication possible")
        if not self.args.enable_keyboard_interactive_auth and not is_trivial_auth:
            return paramiko.common.AUTH_FAILED
        self.session.username = username
        auth_interactive_query = paramiko.server.InteractiveQuery()
        if not self.args.disable_keyboard_interactive_prompts and not is_trivial_auth:
            auth_interactive_query.add_prompt("Password (kb-interactive): ", False)
        return auth_interactive_query

    def check_auth_interactive_response(
        self, responses: List[str]
    ) -> Union[int, paramiko.server.InteractiveQuery]:
        logging.debug("check_auth_interactive_response: responses=%s", responses)
        is_trivial_auth = (
            self.args.enable_trivial_auth and self.session.accepted_key is not None
        )
        if self.args.disable_keyboard_interactive_prompts or is_trivial_auth:
            self.session.authenticator.authenticate(self.session.username, key=None)
            return paramiko.common.AUTH_SUCCESSFUL
        if not responses:
            return paramiko.common.AUTH_FAILED
        return self.session.authenticator.authenticate(
            self.session.username, password=responses[0]
        )

    def check_auth_publickey(self, username: str, key: PKey) -> int:

        # Attempt to access the internal 'sig_attached' variable from Paramiko's
        # authentication handler. This variable indicates whether the SSH public key
        # authentication request includes an attached signature.
        sig_attached: Optional[bool]

        # Retrieve the current stack frame.
        current_frame = inspect.currentframe()

        # Access the parent frame (the caller of this function) and try to get the local
        # variable 'sig_attached' from it.
        sig_attached = current_frame.f_back.f_locals.get("sig_attached")

        # Log detailed information about the current authentication attempt:
        # - username: SSH username being authenticated
        # - key: SSH public key object
        # - key name, fingerprint, and bit length
        # - sig_attached: whether a signature is attached to the authentication request
        logging.info(
            "check_auth_publickey: username=%s, key=%s %s %sbits, sig_attached=%s",
            username,
            key.get_name(),
            key.fingerprint,
            key.get_bits(),
            sig_attached,
        )

        # If 'sig_attached' could not be retrieved, the current version of Paramiko
        # likely does not expose this variable as expected. Raise an exception to
        # indicate that the installed Paramiko version is not compatible.
        if sig_attached is None:
            error_message = (
                "Unable to get 'sig_attached' variable from Paramiko's "
                "AuthHandler._parse_userauth_request. Paramiko version not compatible."
            )
            raise paramiko.ssh_exception.AuthenticationException(error_message)

        if self.session.session_log_dir:
            os.makedirs(self.session.session_log_dir, exist_ok=True)
            pubkeyfile_path = os.path.join(self.session.session_log_dir, "publickeys")
            with open(pubkeyfile_path, "a+", encoding="utf-8") as pubkeyfile:
                pubkeyfile.write(
                    f"{key.get_name()} {key.get_base64()} saved-from-auth-publickey\n"
                )
        if self.args.disable_pubkey_auth:
            logging.debug("Publickey login attempt, but publickey auth was disabled!")
            return paramiko.common.AUTH_FAILED
        if self.args.accept_first_publickey:
            logging.debug("host probing disabled - first key accepted")
            if self.args.disallow_publickey_auth:
                logging.debug(
                    "ignoring argument --disallow-publickey-auth, first key still accepted"
                )
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
        logging.debug(
            "check_auth_password: username=%s, password=%s", username, password
        )
        if self.args.disable_password_auth:
            logging.warning("Password login attempt, but password auth was disabled!")
            return paramiko.common.AUTH_FAILED
        if not self.session.remote_address_reachable:
            return paramiko.common.AUTH_FAILED
        return self.session.authenticator.authenticate(username, password=password)

    def check_channel_request(self, kind: str, chanid: int) -> int:
        logging.debug("check_channel_request: kind=%s , chanid=%s", kind, chanid)
        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_env_request(
        self, channel: paramiko.Channel, name: bytes, value: bytes
    ) -> bool:
        logging.debug(
            "check_channel_env_request: channel=%s, name=%s, value=%s",
            channel,
            name,
            value,
        )
        self.session.env_requests[name] = value
        return True

    def check_channel_subsystem_request(
        self, channel: paramiko.Channel, name: str
    ) -> bool:
        logging.debug(
            "check_channel_subsystem_request: channel=%s, name=%s", channel, name
        )
        if name.lower() == "sftp":
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
        logging.debug("check_port_forward_request: address=%s, port=%s", address, port)
        if self.session.ssh_client is None:
            logging.debug("check_port_forward_request: session.ssh_client is None")
            return False
        if self.session.ssh_client.transport is None:
            logging.debug(
                "check_port_forward_request: session.ssh_client.transport is None"
            )
            return False
        try:
            return self.session.ssh_client.transport.request_port_forward(
                address,
                port,
                self.session.proxyserver.server_tunnel_interface(
                    self.session, self, (address, port)
                ).handler,
            )
        except paramiko.ssh_exception.SSHException:
            logging.info("TCP forwarding request denied")
            return False

    def cancel_port_forward_request(self, address: str, port: int) -> None:
        logging.info("cancel_port_forward_request: address=%s, port=%s", address, port)
        username = self.session.transport.get_username()
        logging.info(
            "Cancel port forward request on %s:%i by %s.",
            address,
            port,
            username,
            extra={"username": username},
        )
        if self.session.ssh_client is None:
            logging.debug("cancel_port_forward_request: session.ssh_client is None!")
            return
        if self.session.ssh_client.transport is None:
            logging.debug(
                "cancel_port_forward_request: session.ssh_client.transport is None!"
            )
            return
        self.session.ssh_client.transport.cancel_port_forward(address, port)

    def check_channel_direct_tcpip_request(
        self, chanid: int, origin: Tuple[str, int], destination: Tuple[str, int]
    ) -> int:
        username = self.session.transport.get_username()
        logging.info(
            "channel_direct_tcpip_request: chanid=%s, origin=%s, destination=%s, username=%s",
            chanid,
            origin,
            destination,
            username,
        )

        try:
            tunnel_forwarder = self.session.proxyserver.client_tunnel_interface(
                self.session, chanid, origin, destination
            )
            self.forwarders.append(tunnel_forwarder)
        except paramiko.ssh_exception.ChannelException:
            logging.error("Could not setup forward from %s to %s.", origin, destination)
            return paramiko.common.OPEN_FAILED_CONNECT_FAILED

        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_window_change_request(  # pylint: disable=too-many-arguments
        self,
        channel: paramiko.Channel,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
    ) -> bool:
        logging.debug(
            "check_channel_window_change_request: channel=%s, width=%s, height=%s, pixelwidth=%s, pixelheight=%s",
            channel,
            width,
            height,
            pixelwidth,
            pixelheight,
        )
        if "ssh " not in self.session._registered_interfaces:
            logging.error("ssh interface not initialized!")
            return False
        self.session._registered_interfaces.server_channel.resize_pty(
            width, height, pixelwidth, pixelheight
        )
        return True

    def check_channel_x11_request(  # pylint: disable=too-many-arguments
        self,
        channel: paramiko.Channel,
        single_connection: bool,
        auth_protocol: str,
        auth_cookie: Union[bytes, bytearray],
        screen_number: int,
    ) -> bool:
        logging.debug(
            "check_channel_x11_request: channel=%s, single_connection=%s, auth_protocol=%s, auth_cookie=%s, screen_number=%s",
            channel,
            single_connection,
            auth_protocol,
            auth_cookie,
            screen_number,
        )
        return False

    def check_global_request(
        self, kind: str, msg: paramiko.message.Message
    ) -> Union[bool, Tuple[Union[bool, int, str], ...]]:
        logging.debug("check_global_request: kind=%s, msg=%s", kind, msg)
        return False


class ProxySFTPServer(paramiko.SFTPServer):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        channel: paramiko.Channel,
        name: str,
        server: ServerInterface,
        sftp_si: Type[paramiko.SFTPServerInterface],
        session: "sshmitm.core.session.Session",
        *largs: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(channel, name, server, sftp_si, *largs, **kwargs)
        self.session = session
        self.session.register_session_thread()
        self.channel = channel

    def _send_server_version(self) -> int:
        # winscp will freak out if the server sends version info before the
        # client finishes sending INIT.
        # check-file was removed, because it's not a common extension, which is used by most clients
        # original implementaion:
        # https://github.com/paramiko/paramiko/blob/d9ab89a0f8ae37a25d44565d5eb03a5d93fed5b9/paramiko/sftp.py#L153

        t, data = self._read_packet()
        if t != CMD_INIT:
            raise SFTPError("Incompatible sftp protocol")  # noqa: TRY003,EM101
        version = struct.unpack(">I", data[:4])[0]
        msg = Message()
        msg.add_int(_VERSION)
        self._send_packet(CMD_VERSION, msg)
        return version

    def start_subsystem(
        self, name: str, transport: paramiko.Transport, channel: paramiko.Channel
    ) -> None:
        with self.session.ssh_client_created:
            self.session.ssh_client_created.wait_for(
                lambda: self.session.ssh_client_auth_finished
            )
            try:
                self.session.sftp_client = SFTPClient.from_client(
                    self.session.ssh_client
                )
                if not self.session.sftp_client:
                    logging.error("no sftp client available")
                    return
                self.session.sftp_client.subsystem_count += 1
                super().start_subsystem(name, transport, channel)
            except Exception:  # pylint: disable=broad-exception-caught # noqa: BLE001
                logging.error("failed to start sftp subsystem - closing subsystem")

    def finish_subsystem(self) -> None:
        self.channel.shutdown_write()
        self.channel.send_exit_status(0)
        if not self.session.sftp_client:
            return
        self.session.sftp_client.subsystem_count -= 1
        self.session.sftp_client.close()
        super().finish_subsystem()
