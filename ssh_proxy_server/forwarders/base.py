import logging

from enhancements.modules import BaseModule


class BaseForwarder(BaseModule):
    """
    base class for all forwarders.
    """

    # Slow file transmission
    BUF_LEN = 65536*100

    def __init__(self, session):
        super().__init__()
        self.server_channel = session.ssh_client.transport.open_session()
        if session.authenticator.args.forward_agent:
            logging.info("Forwarding agent to remote")
            session.agent.forward_agent(self.server_channel)
        self.channel = None
        self.session = session

        # pass environment variables from client to server
        for env_name, env_value in self.session.env_requests.items():
            self.server_channel.set_environment_variable(env_name, env_value)

    def forward(self):
        raise NotImplementedError

    def close_session(self, channel):
        channel.lock.acquire()
        if not channel.closed:
            channel.lock.release()
            channel.close()
        if channel.lock.locked():
            channel.lock.release()

    def _closed(self, channel):
        #return channel.closed or channel.eof_received or channel.eof_sent or not channel.active
        return channel.closed or not channel.active
