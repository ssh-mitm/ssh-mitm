import inspect
import logging
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


class ServerInterface(BaseServerInterface):  # pylint: disable=too-many-public-methods
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
            "--disable-subsystems",
            dest="disable_subsystems",
            action="store_true",
            help="Disables subsystems like SFTP.",
        )
        plugin_group.add_argument(
            "--disable-port-forwarding",
            dest="disable_port_forwarding",
            action="store_true",
            help="Disables subsystems like SFTP.",
        )
        plugin_group.add_argument(
            "--disable-environment-requests",
            dest="disable_environment_requests",
            action="store_true",
            help="Disables environment requests from the ssh client.",
        )
        plugin_group.add_argument(
            "--disable-agent-forwarding",
            dest="disable_agent_forwarding",
            action="store_true",
            help="Disables prompts for keyboard-interactive authentication, preventing interactive authentication challenges.",
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
            self.session.register_forwarder(
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

            self.session.register_forwarder(
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
        if self.args.disable_agent_forwarding:
            return False
        self.session.authenticator.agent_requested.set()
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        logging.debug("check_channel_shell_request: channel=%s", channel)
        if not self.args.disable_ssh:
            self.session.register_forwarder(
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
        return "publickey"

    def check_auth_none(self, username: str) -> int:
        logging.debug("check_auth_none: username=%s", username)
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: Union[bytes, str]
    ) -> Union[int, paramiko.server.InteractiveQuery]:
        logging.debug(
            "check_auth_interactive: username=%s, submethods=%s", username, submethods
        )
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive_response(
        self, responses: List[str]
    ) -> Union[int, paramiko.server.InteractiveQuery]:
        logging.debug("check_auth_interactive_response: responses=%s", responses)
        return paramiko.common.AUTH_FAILED

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

        if not sig_attached:
            return self.check_auth_publickey_pk_lookup(username, key)
        return self.check_auth_publickey_authenticate(username, key)

    def check_auth_publickey_pk_lookup(self, username: str, key: PKey) -> int:
        logging.debug(
            "%s.check_auth_publickey_pk_lookup: username=%s, key=%s",
            self.__class__.__name__,
            username,
            key,
        )
        return paramiko.common.AUTH_FAILED

    def check_auth_publickey_authenticate(self, username: str, key: PKey) -> int:
        logging.debug(
            "%s.check_auth_publickey_authenticate: username=%s, key=%s",
            self.__class__.__name__,
            username,
            key,
        )
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        logging.debug(
            "check_auth_password: username=%s, password=%s", username, password
        )
        return paramiko.common.AUTH_FAILED

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
        if self.args.disable_environment_requests:
            return False
        self.session.env_requests[name] = value
        return True

    def check_channel_subsystem_request(
        self, channel: paramiko.Channel, name: str
    ) -> bool:
        logging.debug(
            "check_channel_subsystem_request: channel=%s, name=%s", channel, name
        )
        if self.args.disable_subsystems:
            return False
        if name.lower() == "sftp":
            self.session.sftp_requested = True
            self.session.sftp_channel = channel
        return super().check_channel_subsystem_request(channel, name)

    def check_port_forward_request(self, address: str, port: int) -> Union[int, bool]:
        """
        Note that the if the client requested the port, we must handle it or
        return false.
        Only if it requested 0 as port we can open a random port (actually the
        OS will tell us which port).
        If it can't be opened, we just return false.
        """
        logging.debug("check_port_forward_request: address=%s, port=%s", address, port)
        if self.args.disable_port_forwarding:
            logging.debug("port forwarding disabled")
            return False

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
        logging.debug("cancel_port_forward_request: address=%s, port=%s", address, port)
        username = self.session.transport.get_username()
        logging.info(
            "Cancel port forward request on %s:%i by %s.",
            address,
            port,
            username,
            extra={"username": username},
        )
        if self.args.disable_port_forwarding:
            logging.warning(
                "port forwarding disabled but got cancel_port_forward_request"
            )
            return
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
        if self.args.disable_port_forwarding:
            logging.debug("port forwarding disabled")
            return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
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
        if not self.session.get_forwarder("ssh"):
            logging.error("ssh interface not initialized!")
            return False
        self.session.get_forwarder("ssh").server_channel.resize_pty(
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
        with self.session.authenticator.ssh_client_created:
            self.session.authenticator.ssh_client_created.wait_for(
                self.session.authenticator.ssh_client_auth_finished.is_set
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
