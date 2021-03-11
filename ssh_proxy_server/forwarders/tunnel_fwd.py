import logging
import select
import threading

from enhancements.modules import BaseModule


class BaseTunnelForwarder(BaseModule):
    pass


class TunnelForwarder(threading.Thread, BaseTunnelForwarder):

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
        Connect a socket and a SSH channel.
        TODO: Plugin/Interface compatibility can be inserted HERE (or one layer above)
        """
        while True:
            r, w, x = select.select([self.local_ch, self.remote_ch], [], [])

            if self.local_ch in r:
                data = self.local_ch.recv(chunk_size)
                if len(data) == 0:
                    break
                self.remote_ch.send(data)

            if self.remote_ch in r:
                data = self.remote_ch.recv(chunk_size)
                if len(data) == 0:
                    break
                self.local_ch.send(data)

    def close(self):
        close_channel(self.local_ch)
        close_channel(self.remote_ch)

def close_channel(channel):
    # TODO: format all channel closes like this
    channel.lock.acquire()
    if not channel.closed:
        channel.close()
    channel.lock.release()
