import logging
import time

from ssh_proxy_server.forwarders.tunnel_fwd import TunnelForwarder


class ProxyTunnelForwarder(TunnelForwarder):
    """
    TODO: Make a plugin that also opens a local port on the ssh-mitm over witch the server can send requests
    Open direct-tcpip channel to remote and tell it to open a direct-tcpip channel to the destination
    Then forward traffic between channels connecting to local and to remote through the ssh-mitm
        - supports Proxyjump (-W / -J) feature
        - support client side port forwarding (-L)
    """

    # mode 0 = -L; mode 1 = -R
    LOCAL_FWD = 0
    REMOTE_FWD = 1

    def __init__(self, session, channel, origin, destination, mode):
        self.session = session
        self.channel = channel
        self.origin = origin
        self.destination = destination
        self.mode = mode
        if mode == self.LOCAL_FWD:
            logging.debug("Forwarding direct-tcpip request (%s -> %s) to remote", self.origin, self.destination)
            remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", self.destination, self.origin)
            super(ProxyTunnelForwarder, self).__init__(None, remote_ch)
        elif mode == self.REMOTE_FWD:
            logging.debug("Opening forwarded-tcpip channel (%s -> %s) to client", self.origin, self.destination)
            local_ch = self.session.transport.open_channel("forwarded-tcpip", self.destination, self.origin)
            super(ProxyTunnelForwarder, self).__init__(local_ch, channel)

    def run(self) -> None:
        # Channel setup in thread start - so that transport thread can return to the session thread
        # Wait for master channel establishment
        if self.mode == self.LOCAL_FWD:
            while not self.session.transport.channels_seen:
                time.sleep(0.1)
            if self.channel.get_id() in self.session.transport.channels_seen.keys():  # chanid: 0
                # Proxyjump (-W / -J) will use the already established master channel
                # stdin and stdout of that channel have to be forwarded over to the ssh-client direct-tcpip channel
                self.local_ch = self.session.channel
                logging.debug("Proxyjump: forwarding traffic through master channel [chanid %s]", self.channel.get_id())
            if not self.local_ch:
                self.local_ch = self.session.transport.accept(5)
        super(ProxyTunnelForwarder, self).run()
