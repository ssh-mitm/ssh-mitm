from abc import abstractmethod
from typing import TYPE_CHECKING, Optional

import paramiko

from sshmitm.exceptions import MissingClient
from sshmitm.moduleparser import BaseModule

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.session import Session


class BaseForwarder(BaseModule):
    """
    base class for all forwarders.
    """

    # Slow file transmission
    BUF_LEN = 65536 * 100

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__()
        if session.ssh_client is None or session.ssh_client.transport is None:
            msg = "session.ssh_client is None"
            raise MissingClient(msg)
        self.server_channel: paramiko.Channel = (
            session.ssh_client.transport.open_session()
        )
        if session.agent is not None:
            session.agent.forward_agent(self.server_channel)
        self.session: "Session" = session
        self.session.register_session_thread()

        # pass environment variables from client to server
        for env_name, env_value in self.session.env_requests.items():
            self.server_channel.set_environment_variable(env_name, env_value)

    @property
    @abstractmethod
    def client_channel(self) -> Optional[paramiko.Channel]:
        """Returns the client channel for the current plugin type"""

    @abstractmethod
    def forward(self) -> None:
        """Forwards data between the client and the server"""

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
