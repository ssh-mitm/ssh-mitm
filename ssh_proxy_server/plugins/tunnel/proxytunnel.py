import logging
import time

from ssh_proxy_server.forwarders.tunnel_fwd import TunnelForwarder


class ProxyTunnelForwarder(TunnelForwarder):
    """
    Open direct_tcpip channel to remote and tell it to open a direct_tcpip channel to the destination
    then forward traffic between these 2 channels on the ssh-mitm
    """

    def __init__(self, session, chanid, origin, destination):
        self.session = session
        self.chanid = chanid
        self.origin = origin
        self.destination = destination
        remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", self.destination, self.origin)
        super(ProxyTunnelForwarder, self).__init__(None, remote_ch)

    def run(self) -> None:
        # Channel setup in thread start - so that transport thread can return to the session thread
        local_ch = None
        while not self.session.transport.channels_seen:
            time.sleep(0.3)
        if self.chanid in self.session.transport.channels_seen.keys():
            # when the ssh-client is using the proxyjump feature (-W) no direct ssh-shell will be requested by the
            # client and stdin and stdout is connected to the master channel
            local_ch = self.session.channel
        logging.debug(self.session.transport.channels_seen)
        if not local_ch:
            local_ch = self.session.transport.accept(5)
        self.local_ch = local_ch
        logging.debug(local_ch)
        super(ProxyTunnelForwarder, self).run()
        # TODO: Fix close (Jumphost RC)

