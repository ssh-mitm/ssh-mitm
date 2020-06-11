from enhancements.modules import Module


class BaseForwarder(Module):
    """
    base class for all forwarders.
    """

    BUF_LEN = 8192

    def __init__(self, session):
        super().__init__()
        self.server_channel = session.ssh_client.transport.open_session()
        self.channel = None
        self.session = session

    def forward(self):
        raise NotImplementedError

    @staticmethod
    def _closed(channel):
        return channel.closed or channel.eof_received or channel.eof_sent or not channel.active
