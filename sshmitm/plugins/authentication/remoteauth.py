import logging

import paramiko
from paramiko import PKey

from sshmitm.core.authentication import Authenticator
from sshmitm.core.clients.ssh import AuthenticationMethod


class AuthenticatorRemote(Authenticator):

    @classmethod
    def parser_arguments(cls) -> None:
        super().parser_arguments()
        cls.argument_group()

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
