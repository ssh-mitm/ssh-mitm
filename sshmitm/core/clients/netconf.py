import logging
from enum import Enum
from typing import TYPE_CHECKING, Optional

from paramiko.pkey import PKey

from sshmitm.core.clients.ssh import SSHClient

if TYPE_CHECKING:
    import sshmitm


class AuthenticationMethod(Enum):
    """
    An enumeration of possible authentication methods that can be
    used to connect to a remote host.
    """

    PASSWORD = "password"  # nosec # noqa: S105
    PUBLICKEY = "publickey"
    AGENT = "agent"


class NetconfClient(SSHClient):
    """
    The SSH client class, used to connect to a remote host with the netconf subsystem.

    :param host: the hostname or IP address of the remote host
    :param port: the port number to connect to on the remote host
    :param method: the authentication method to use when connecting
    :param password: the password to use for authentication (if method is `password`)
    :param user: the username to use for authentication
    :param key: the public key to use for authentication (if method is `publickey`)
    :param session: the session instance
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        host: str,
        port: int,
        method: AuthenticationMethod,
        password: Optional[str],
        user: str,
        key: Optional[PKey],
        session: "sshmitm.core.session.Session",
    ) -> None:
        super().__init__(host, port, method, password, user, key, session)
        self.subsystem_count = 0

    @classmethod
    def from_client(cls, ssh_client: Optional[SSHClient]) -> Optional["NetconfClient"]:
        """
        Create an NetconfClient instance from an SSHClient instance.

        :param ssh_client: The SSHClient instance.
        :return: An NetconfClient instance, or None if the NetconfClient could not be created.
        """
        if ssh_client is None:
            logging.error("error creating netconf client - no ssh client!")
            return None
        if not ssh_client.connected and ssh_client.connect():
            logging.error("error creating netconf client!")
            return None

        try:
            netconf = cls(
                ssh_client.host,
                ssh_client.port,
                ssh_client.method,
                ssh_client.password,
                ssh_client.user,
                ssh_client.key,
                ssh_client.session,
            )
            if ssh_client.transport is None:
                logging.debug("ssh_client does not have a transport")
                return None
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("error creating netconf client")
            return None
        netconf.connected = True
        return netconf

    @property
    def running(self) -> bool:
        """
        Indicate whether the netconf client is running.

        :return: Whether the netconf client is running.
        """
        return self.subsystem_count > 0
