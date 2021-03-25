import logging
import select
import threading
import time

import paramiko
from enhancements.modules import BaseModule


class TunnelForwarder(threading.Thread):

    def __init__(self, local_ch, remote_ch):
        super(TunnelForwarder, self).__init__()
        self.local_ch = local_ch
        self.remote_ch = remote_ch
        self.start()

    def run(self) -> None:
        try:
            self.tunnel()
        except Exception:
            logging.exception("Tunnel exception with peer")
        self.close()

    def tunnel(self, chunk_size=1024):
        """
        Connect two SSH channels (socket like objects).
        """
        while True:
            r, w, x = select.select([self.local_ch, self.remote_ch], [], [])

            if self.local_ch in r:
                data = self.local_ch.recv(chunk_size)
                data = self.handle_data_from_local(data)
                if len(data) == 0:
                    break
                self.remote_ch.send(data)

            if self.remote_ch in r:
                data = self.remote_ch.recv(chunk_size)
                data = self.handle_data_from_remote(data)
                if len(data) == 0:
                    break
                self.local_ch.send(data)

    def handle_data(self, data):
        return data

    def handle_data_from_remote(self, data):
        return self.handle_data(data)

    def handle_data_from_local(self, data):
        return self.handle_data(data)

    def close(self):
        """
        Comparable with Channels and Sockets
        """
        if self.local_ch:
            self.close_channel(self.local_ch)
        if self.remote_ch:
            self.close_channel(self.remote_ch)

    def close_channel(self, channel):
        if not isinstance(channel, paramiko.Channel): # socket.socket
            channel.close()
            return
        channel.lock.acquire()
        if not channel.closed:
            channel.lock.release()
            channel.close()
        if channel.lock.locked():
            channel.lock.release()


class ClientTunnelBaseForwarder(BaseModule):
    pass


class ClientTunnelForwarder(TunnelForwarder, ClientTunnelBaseForwarder):
    """Handles tunnel forwarding when the client is requesting a tunnel connection

    Then forward traffic between direct-tcpip channels connecting to local and to remote through the ssh-mitm
        - implements Proxyjump (-W / -J) feature, client side port forwarding (-L)
    """

    def __init__(self, session, chanid, origin, destination):
        self.session = session
        self.chanid = chanid
        self.origin = origin
        self.destination = destination
        logging.debug("Forwarding direct-tcpip request (%s -> %s) to remote", self.origin, self.destination)
        remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", self.destination, self.origin)
        super(ClientTunnelForwarder, self).__init__(None, remote_ch)

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
        super(ClientTunnelForwarder, self).run()


class ServerTunnelBaseForwarder(BaseModule):
    pass


class ServerTunnelForwarder(ServerTunnelBaseForwarder):
    """Handles Tunnel forwarding when the server is requesting a tunnel connection

    Actually just used to wrap data around a handler to parse to the transport.request_port_forward
    -> that is why it does not inherit the TunnelForwarder; it just uses it in the handler
    """

    def __init__(self, session, server_interface, destination):
        super(ServerTunnelBaseForwarder, self).__init__()
        self.session = session
        self.server_interface = server_interface
        self.destination = destination

    def handler(self, channel, origin, destination):
        try:
            logging.debug("Opening forwarded-tcpip channel (%s -> %s) to client", origin, destination)
            f = TunnelForwarder(
                self.session.transport.open_channel("forwarded-tcpip", destination, origin),
                channel
            )
            self.server_interface.forwarders.append(f)
        except paramiko.ssh_exception.ChannelException:
            channel.close()
            logging.error("Could not setup forward from %s to %s.", origin, destination)
