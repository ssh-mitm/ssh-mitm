import logging
import select
import threading
import time

from enhancements.modules import BaseModule


class BaseTunnelForwarder(threading.Thread, BaseModule):

    def __init__(self, local_ch, remote_ch):
        super(BaseTunnelForwarder, self).__init__()
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
        self.close_channel(self.local_ch)
        self.close_channel(self.remote_ch)

    def close_channel(self, channel):
        channel.lock.acquire()
        if not channel.closed:
            channel.lock.release()
            channel.close()
        if channel.lock.locked():
            channel.lock.release()


class TunnelForwarder(BaseTunnelForwarder):
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
            super(TunnelForwarder, self).__init__(None, remote_ch)
        elif mode == self.REMOTE_FWD:
            logging.debug("Opening forwarded-tcpip channel (%s -> %s) to client", self.origin, self.destination)
            local_ch = self.session.transport.open_channel("forwarded-tcpip", self.destination, self.origin)
            super(TunnelForwarder, self).__init__(local_ch, channel)

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
        super(TunnelForwarder, self).run()
