import logging
import select
import threading
import time
from socket import socket
from typing import (
    TYPE_CHECKING,
    Optional,
    Tuple,
    Union
)

import paramiko

import sshmitm
from sshmitm.moduleparser import BaseModule

if TYPE_CHECKING:
    from sshmitm.session import Session  # noqa


class TunnelForwarder(threading.Thread):

    def __init__(
        self, local_ch: Optional[Union[socket, paramiko.Channel]], remote_ch: Optional[Union[socket, paramiko.Channel]]
    ) -> None:
        super().__init__()
        self.local_ch = local_ch
        self.remote_ch = remote_ch
        self.start()

    def run(self) -> None:
        try:
            self.tunnel()
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Tunnel exception with peer")
        self.close()

    def tunnel(self, chunk_size: int = 1024) -> None:
        """
        Connect two SSH channels (socket like objects).
        """
        while True:
            if self.local_ch is None:
                logging.error("local channel is None")
                break
            if self.remote_ch is None:
                logging.error("remote channel is None")
                break

            socklist_read, _, _ = select.select([self.local_ch, self.remote_ch], [], [])

            if self.local_ch in socklist_read:
                data = self.local_ch.recv(chunk_size)
                data = self.handle_data_from_local(data)
                if len(data) == 0:
                    break
                self.remote_ch.send(data)

            if self.remote_ch in socklist_read:
                data = self.remote_ch.recv(chunk_size)
                data = self.handle_data_from_remote(data)
                if len(data) == 0:
                    break
                self.local_ch.send(data)

    def handle_data(self, data: bytes) -> bytes:
        return data

    def handle_data_from_remote(self, data: bytes) -> bytes:
        return self.handle_data(data)

    def handle_data_from_local(self, data: bytes) -> bytes:
        return self.handle_data(data)

    def close(self) -> None:
        """
        Comparable with Channels and Sockets
        """
        if self.local_ch:
            self.close_channel(self.local_ch)
        if self.remote_ch:
            self.close_channel(self.remote_ch)

    def close_channel(self, channel: Union[socket, paramiko.Channel]) -> None:
        if not isinstance(channel, paramiko.Channel):  # socket.socket
            channel.close()
            return
        channel.lock.acquire()
        if not channel.closed:
            channel.lock.release()
            channel.close()
        if channel.lock.locked():
            channel.lock.release()


class LocalPortForwardingBaseForwarder(BaseModule):
    pass


class LocalPortForwardingForwarder(TunnelForwarder, LocalPortForwardingBaseForwarder):
    """Handles tunnel forwarding when the client is requesting a tunnel connection

    Then forward traffic between direct-tcpip channels connecting to local and to remote through the ssh-mitm
        - implements Proxyjump (-W / -J) feature, client side port forwarding (-L)
    """

    def __init__(
        self,
        session: 'sshmitm.session.Session',
        chanid: int,
        origin: Optional[Tuple[str, int]],
        destination: Optional[Tuple[str, int]]
    ) -> None:
        self.session = session
        self.chanid = chanid
        self.origin = origin
        self.destination = destination
        logging.debug("Forwarding direct-tcpip request (%s -> %s) to remote", self.origin, self.destination)
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            raise ValueError("No SSH client!")
        remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", self.destination, self.origin)
        super().__init__(None, remote_ch)

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
        super().run()

    @classmethod
    def setup(cls, session: 'sshmitm.session.Session') -> None:
        pass


class RemotePortForwardingBaseForwarder(BaseModule):
    pass


class RemotePortForwardingForwarder(RemotePortForwardingBaseForwarder):
    """Handles Tunnel forwarding when the server is requesting a tunnel connection

    Actually just used to wrap data around a handler to parse to the transport.request_port_forward
    -> that is why it does not inherit the TunnelForwarder; it just uses it in the handler
    """

    def __init__(
        self,
        session: 'sshmitm.session.Session',
        server_interface: 'sshmitm.interfaces.server.ServerInterface',
        destination: Optional[Tuple[str, int]]
    ) -> None:
        super(RemotePortForwardingBaseForwarder, self).__init__()
        self.session = session
        self.server_interface = server_interface
        self.destination = destination

    def join(self) -> None:
        pass

    def close(self) -> None:
        pass

    def handler(
        self, channel: paramiko.Channel, origin: Optional[Tuple[str, int]], destination: Optional[Tuple[str, int]]
    ) -> None:
        try:
            logging.debug("Opening forwarded-tcpip channel (%s -> %s) to client", origin, destination)
            forwarded_tunnel = TunnelForwarder(
                self.session.transport.open_channel("forwarded-tcpip", destination, origin),
                channel
            )
            self.server_interface.forwarders.append(forwarded_tunnel)
        except paramiko.ssh_exception.ChannelException:
            channel.close()
            logging.error("Could not setup forward from %s to %s.", origin, destination)
