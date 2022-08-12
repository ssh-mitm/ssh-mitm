from typing import (
    TYPE_CHECKING,
    Optional
)

import paramiko

import sshmitm
from sshmitm.moduleparser import BaseModule
from sshmitm.exceptions import MissingClient
if TYPE_CHECKING:
    from sshmitm.session import Session


class BaseForwarder(BaseModule):
    """
    base class for all forwarders.
    """

    # Slow file transmission
    BUF_LEN = 65536 * 100

    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super().__init__()
        if session.ssh_client is None or session.ssh_client.transport is None:
            raise MissingClient("session.ssh_client is None")
        self.server_channel: paramiko.Channel = session.ssh_client.transport.open_session()
        if session.agent is not None:
            session.agent.forward_agent(self.server_channel)
        self.channel: Optional[paramiko.Channel] = None
        self.session: 'Session' = session

        # pass environment variables from client to server
        for env_name, env_value in self.session.env_requests.items():
            self.server_channel.set_environment_variable(env_name, env_value)

    def forward(self) -> None:
        raise NotImplementedError

    def close_session(self, channel: paramiko.Channel) -> None:
        channel.lock.acquire()
        if not channel.closed:
            channel.lock.release()
            channel.close()
        if channel.lock.locked():
            channel.lock.release()

    def _closed(self, channel: paramiko.Channel) -> bool:
        # return channel.closed or channel.eof_received or channel.eof_sent or not channel.active
        return channel.closed or not channel.active
