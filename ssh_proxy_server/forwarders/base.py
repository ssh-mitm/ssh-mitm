import logging

from paramiko.agent import AgentRequestHandler
from enhancements.modules import Module


class BaseForwarder(Module):
    """
    base class for all forwarders.
    """

    BUF_LEN = 8192

    def __init__(self, session):
        super().__init__()
        self.server_channel = session.ssh_client.transport.open_session()
        # if session.agent:   # Experimental
        #     logging.info("Forwarding agent to remote")
        #     AgentRequestHandler(self.server_channel)
        self.channel = None
        self.session = session

    def forward(self):
        raise NotImplementedError

    def close_session(self, channel):
        channel.close()

    def _closed(self, channel):
        return channel.closed or channel.eof_received or channel.eof_sent or not channel.active
