import os
import time
from typing import List, Tuple, Union

from paramiko.agent import Agent, AgentClientProxy, AgentKey, AgentServerProxy
from paramiko.channel import Channel
from paramiko.transport import Transport


class AgentProxy:
    def __init__(self, transport: Transport) -> None:
        self.agents: List[Union[Agent, AgentClientProxy]] = []
        self.transport = transport
        agent_proxy = AgentServerProxy(self.transport)
        os.environ.update(agent_proxy.get_env())
        agent_proxy.connect()
        self.agent = Agent()
        self.keys = self.agent.get_keys()[:]
        self.agents.append(self.agent)
        # should be able to be closed now, but for some reason there is a race
        # agent is still sending over the channel
        # agent.close()  # noqa: ERA001

    def get_keys(self) -> Tuple[AgentKey, ...]:
        return self.keys

    def forward_agent(self, client_channel: Channel) -> bool:
        return client_channel.request_forward_agent(self._forward_agent_handler)

    def _forward_agent_handler(self, remote_channel: Channel) -> None:
        agent = AgentServerProxy(self.transport)
        os.environ.update(agent.get_env())
        time.sleep(0.1)
        self.agents.append(AgentClientProxy(remote_channel))

    def close(self) -> None:
        for agent_proxy in self.agents:
            agent_proxy.close()
