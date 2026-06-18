import logging
from typing import TYPE_CHECKING, Optional

from paramiko.pkey import PKey

from sshmitm.clients.ssh import AuthenticationMethod, SSHClient

if TYPE_CHECKING:
    import sshmitm


class PowerShellClient(SSHClient):
    """
    SSH client used to connect to a remote host with the PowerShell remoting subsystem.

    PowerShell remoting over SSH (PSRP) is started on the remote host with
    ``pwsh -sshs`` registered as the ``powershell`` SSH subsystem.  This client
    reuses the transport of an already authenticated :class:`SSHClient` and only
    tracks how many subsystem channels are currently active.

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
        password: str | None,
        user: str,
        key: PKey | None,
        session: "sshmitm.session.Session",
    ) -> None:
        super().__init__(host, port, method, password, user, key, session)
        self.subsystem_count = 0

    @classmethod
    def from_client(cls, ssh_client: SSHClient | None) -> Optional["PowerShellClient"]:
        """
        Create a PowerShellClient instance from an SSHClient instance.

        :param ssh_client: The SSHClient instance.
        :return: A PowerShellClient instance, or None if it could not be created.
        """
        if ssh_client is None:
            logging.error("error creating powershell client - no ssh client!")
            return None
        if not ssh_client.connected and not ssh_client.connect():
            logging.error("error creating powershell client!")
            return None

        try:
            powershell = cls(
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
            logging.exception("error creating powershell client")
            return None
        powershell.connected = True
        return powershell

    @property
    def running(self) -> bool:
        """
        Indicate whether the powershell client is running.

        :return: Whether the powershell client is running.
        """
        return self.subsystem_count > 0

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
