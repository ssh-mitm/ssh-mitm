import time
from typing import Tuple, List, Union

from paramiko.agent import Agent, AgentKey, AgentServerProxy, AgentClientProxy
from paramiko.transport import Transport
from paramiko.channel import Channel
import os

from typeguard import typechecked


class AgentProxy(object):

    @typechecked
    def __init__(self, transport: Transport) -> None:
        self.agents: List[Union[Agent, AgentClientProxy]] = []
        self.transport = transport
        a = AgentServerProxy(self.transport)
        os.environ.update(a.get_env())
        a.connect()
        self.agent = Agent()
        self.keys = self.agent.get_keys()[:]
        self.agents.append(self.agent)
        # should be able to be closed now, but for some reason there is a race
        # agent is still sending over the channel
        # agent.close()

    @typechecked
    def get_keys(self) -> Tuple[AgentKey, ...]:
        return self.keys

    @typechecked
    def forward_agent(self, chanClient: Channel) -> bool:
        return chanClient.request_forward_agent(self._forward_agent_handler)

    @typechecked
    def _forward_agent_handler(self, chanRemote: Channel) -> None:
        agent = AgentServerProxy(self.transport)
        os.environ.update(agent.get_env())
        time.sleep(0.1)
        self.agents.append(AgentClientProxy(chanRemote))

    @typechecked
    def close(self) -> None:
        for a in self.agents:
            a.close()
