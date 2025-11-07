import logging
from typing import TYPE_CHECKING, List, Optional

import paramiko
from paramiko.pkey import PKey

from sshmitm.core.interfaces.server import ServerInterface

if TYPE_CHECKING:
    import sshmitm


class PubkeyOnlyServerInterface(ServerInterface):

    def __init__(self, session: "sshmitm.core.session.Session") -> None:
        super().__init__(session)
        self.possible_auth_methods: Optional[List[str]] = None

    @classmethod
    def parser_arguments(cls) -> None:
        super().parser_arguments()
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--auth-username",
            dest="auth_username",
            help="username which is allowed to login to the proxy server",
        )
        plugin_group.add_argument(
            "--auth-key-sha256",
            dest="auth_key_sha256",
            help="sha256 hash value of allowed public key",
        )

    def get_allowed_auths(self, username: str) -> str:
        del username
        return "publickey"

    def check_auth_publickey_pk_lookup(self, username: str, key: PKey) -> int:
        logging.debug(
            "%s.check_auth_publickey_pk_lookup: username=%s, key=%s",
            self.__class__.__name__,
            username,
            key,
        )
        if (
            username == self.args.auth_username
            and key.fingerprint == self.args.auth_key_sha256
        ):
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_publickey_authenticate(self, username: str, key: PKey) -> int:
        logging.debug(
            "%s.check_auth_publickey_authenticate: username=%s, key=%s",
            self.__class__.__name__,
            username,
            key,
        )
        if (
            self.check_auth_publickey_pk_lookup(username, key)
            == paramiko.common.AUTH_SUCCESSFUL
        ):
            return self.session.authenticator.authenticate(username, key=key)
        return paramiko.common.AUTH_FAILED
