import time

from paramiko.agent import Agent, AgentServerProxy, AgentClientProxy
import os

class AgentProxy(object):

    def __init__(self, transport) -> None:
        self.agents = []
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

    def get_keys(self):
        return self.keys

    def forward_agent(self, chanClient):
        chanClient.request_forward_agent(self._forward_agent_handler)

    def _forward_agent_handler(self, chanRemote):
        agent = AgentServerProxy(self.transport)
        os.environ.update(agent.get_env())
        time.sleep(0.1)
        self.agents.append(AgentClientProxy(chanRemote))

    def close(self):
        for a in self.agents:
            a.close()
