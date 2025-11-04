import os
import time
from typing import List, Tuple, Union

from paramiko.agent import Agent, AgentClientProxy, AgentKey, AgentServerProxy
from paramiko.channel import Channel
from paramiko.transport import Transport


class AgentProxy:
    """
    A proxy class to manage SSH agent forwarding over a Paramiko Transport.

    This class sets up an SSH agent proxy server, retrieves available keys,
    and handles agent forwarding between remote channels and the local SSH agent.
    """

    def __init__(self, transport: Transport) -> None:
        """
        Initialize the agent proxy for the given SSH transport.

        This creates a local agent server proxy and registers the local agent
        to enable agent forwarding through the SSH session.

        :param transport: The Paramiko Transport associated with the SSH connection.
        """
        self._registered_agents: List[Union[Agent, AgentClientProxy]] = []
        self.transport = transport

        # Create an agent server proxy tied to the transport and register its environment
        agent_proxy = AgentServerProxy(self.transport)
        os.environ.update(agent_proxy.get_env())
        agent_proxy.connect()

        # Retrieve local agent keys and register the agent
        agent = Agent()
        self._keys = agent.get_keys()[:]
        self._registered_agents.append(agent)

    def get_keys(self) -> Tuple[AgentKey, ...]:
        """
        Return the list of available SSH agent keys.

        :returns: A tuple containing all available AgentKey objects.
        """
        return self._keys

    def forward_agent(self, client_channel: Channel) -> bool:
        """
        Request agent forwarding on the specified SSH channel.

        This sets up a handler to manage agent forwarding once the request is approved.

        :param client_channel: The SSH channel for which agent forwarding is requested.
        :returns: True if the forwarding request was successful, False otherwise.
        """
        return client_channel.request_forward_agent(self._forward_agent_handler)

    def _forward_agent_handler(self, remote_channel: Channel) -> None:
        """
        Internal handler invoked when a remote channel requests agent forwarding.

        A new agent proxy is established for the remote channel, and the
        environment variables are updated accordingly.

        :param remote_channel: The remote SSH channel initiating the forwarding.
        """
        agent = AgentServerProxy(self.transport)
        os.environ.update(agent.get_env())

        # Wait briefly to ensure the environment and channel are ready
        time.sleep(0.1)

        # Register a client proxy to handle agent communication
        self._registered_agents.append(AgentClientProxy(remote_channel))

    def close(self) -> None:
        """
        Close all registered SSH agent proxies and clean up resources.

        This ensures that all agent client and server proxies are properly terminated.
        """
        for registered_agent_proxy in self._registered_agents:
            registered_agent_proxy.close()
