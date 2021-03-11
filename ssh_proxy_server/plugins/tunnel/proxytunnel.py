import logging
import time

from ssh_proxy_server.forwarders.tunnel_fwd import TunnelForwarder


class ProxyTunnelForwarder(TunnelForwarder):
    """
    Open direct-tcpip channel to remote and tell it to open a direct-tcpip channel to the destination
    Then forward traffic between channels connecting to local and to remote through the ssh-mitm
        - supports Proxyjump (-W / -J) feature
    """

    def __init__(self, session, chanid, origin, destination):
        self.session = session
        self.chanid = chanid
        self.origin = origin
        self.destination = destination
        logging.debug("Forwarding direct-tcpip request (%s -> %s) to remote", self.origin, self.destination)
        remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", self.destination, self.origin)
        super(ProxyTunnelForwarder, self).__init__(None, remote_ch)

    def run(self) -> None:
        # Channel setup in thread start - so that transport thread can return to the session thread
        # Wait for master channel establishment
        while not self.session.transport.channels_seen:
            time.sleep(0.1)
        if self.chanid in self.session.transport.channels_seen.keys():  # chanid: 0
            # Proxyjump (-W / -J) will use the already established master channel
            # stdin and stdout of that channel have to be forwarded over to the ssh-client direct-tcpip channel
            self.local_ch = self.session.channel
            logging.debug("Proxyjump: forwarding traffic through master channel [chanid %s]", self.chanid)
        if not self.local_ch:
            self.local_ch = self.session.transport.accept(5)
        super(ProxyTunnelForwarder, self).run()
