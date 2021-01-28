import threading
import time

from paramiko.agent import Agent, AgentRequestHandler, AgentServerProxy, AgentClientProxy
import logging
import os

class AgentProxy(object):

    def __init__(self, transport) -> None:
        self.agents = []
        self.transport = transport
        agent = AgentServerProxy(self.transport)
        os.environ.update(agent.get_env())
        agent.connect()

        self.agents.append(agent)
        agent = Agent()
        self.keys = agent.get_keys()[:]

        self.agents.append(agent)
        # should be able to be closed now, but for some reason there is a race
        # self.a.close()

    def get_keys(self):
        return self.keys

    def forward_agent(self, chanClient):
        logging.info("Forwarding agent to remote")
        chanClient.request_forward_agent(self._forward_agent_handler)

    def _forward_agent_handler(self, chanRemote):
        agent = AgentServerProxy(self.transport)
        os.environ.update(agent.get_env())
        self.agents.append(AgentClientProxy(chanRemote))

    def wait_for_agent(self, agent):
        while agent._conn is None:
            time.sleep(0.2)

    def close(self):
        for a in self.agents:
            a.close()
