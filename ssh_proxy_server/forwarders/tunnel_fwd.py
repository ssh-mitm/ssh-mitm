import logging
import select
import threading

from enhancements.modules import BaseModule


class BaseTunnelForwarder(BaseModule):
    pass


class TunnelForwarder(threading.Thread, BaseTunnelForwarder):
    # TODO: Make this BaseTunnelForwrader and Proxytunnel this

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
        Connect direct-tcpip and a SSH channel.
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