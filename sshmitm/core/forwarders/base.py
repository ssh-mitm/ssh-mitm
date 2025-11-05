from abc import abstractmethod
from typing import TYPE_CHECKING, Optional

import paramiko

from sshmitm.core.exceptions import MissingClient
from sshmitm.moduleparser import BaseModule

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.core.session import Session


class BaseForwarder(BaseModule):
    """
    base class for all forwarders.
    """

    # Slow file transmission
    BUF_LEN = 65536 * 100

    def __init__(self, session: "sshmitm.core.session.Session") -> None:
        super().__init__()

        self.session: "Session" = session
        self._client_channel: Optional[paramiko.Channel] = None
        self._server_channel: Optional[paramiko.Channel] = None
        self.session.register_session_thread()

    @property
    def client_channel(self) -> Optional[paramiko.Channel]:
        """Returns the client channel for the current plugin type"""
        return self._client_channel

    @client_channel.setter
    def client_channel(self, channel: paramiko.Channel) -> None:
        self._client_channel = channel

    @property
    def server_channel(self) -> Optional[paramiko.Channel]:
        return self._server_channel

    @abstractmethod
    def forward(self) -> None:
        """Forwards data between the client and the server"""
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            msg = "session.ssh_client is None"
            raise MissingClient(msg)
        self._server_channel = self.session.ssh_client.transport.open_session()
        self.session.authenticator.forward_agent_to_remote(self._server_channel)

        # pass environment variables from client to server
        for env_name, env_value in self.session.env_requests.items():
            self._server_channel.set_environment_variable(env_name, env_value)

    def close_session(self, channel: paramiko.Channel) -> None:
        channel.lock.acquire()
        if not channel.closed:
            channel.lock.release()
            channel.close()
        if channel.lock.locked():
            channel.lock.release()

    def _closed(self, channel: paramiko.Channel) -> bool:
        # return channel.closed or channel.eof_received or channel.eof_sent or not channel.active  # noqa: ERA001
        return channel.closed or not channel.active
