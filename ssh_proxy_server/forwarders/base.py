import logging

from enhancements.modules import BaseModule


class BaseForwarder(BaseModule):
    """
    base class for all forwarders.
    """

    # Slow file transmission
    BUF_LEN = 65536

    def __init__(self, session):
        super().__init__()
        self.server_channel = session.ssh_client.transport.open_session()
        if session.authenticator.args.forward_agent:
            logging.info("Forwarding agent to remote")
            session.agent.forward_agent(self.server_channel)
        self.channel = None
        self.session = session

    def forward(self):
        raise NotImplementedError

    def close_session(self, channel):
        channel.close()

    def _closed(self, channel):
        return channel.closed or channel.eof_received or channel.eof_sent or not channel.active
