"""
A Python module for a TCP server that runs as a thread and accepts incoming connections.

This module contains the TCPServerThread class, which implements a basic TCP server that listens for incoming connections and launches a new thread for each connection request.

Example usage:

.. code-block::

    from sshmitm.plugins.session.tcpserver import TCPServerThread

    def handle_request(server_address, client_socket, client_address):
        print("Received connection from", client_address)
        client_socket.sendall(b"Hello, client!")
        client_socket.close()

    server = TCPServerThread(request_handler=handle_request, port=1234)
    server.start()
"""

import select
import socket
import threading
import time
from typing import (
    Callable,
    List,
    Union,
    Tuple,
    Optional
)
import paramiko


class TCPServerThread(threading.Thread):

    """
    A TCP server thread that accepts incoming connections and launches a new thread for each connection.

    :param request_handler: a function to be called for each connection request
    :type request_handler: Optional[Callable[Tuple[str, int], Union[socket.socket, paramiko.Channel], Tuple[str, int]], None]
    :param network: network address for the server to bind to
    :type network: str
    :param port: port number for the server to listen on
    :type port: int
    :param run_status: whether the server should run or not
    :type run_status: bool
    :param daemon: whether the server should run as a daemon
    :type daemon: bool
    :return: None
    """

    def __init__(
        self,
        request_handler: Optional[Callable[
            [Tuple[str, int], Union[socket.socket, paramiko.Channel], Tuple[str, int]],
            None
        ]] = None,
        network: str = '127.0.0.1',
        port: int = 0,
        run_status: bool = True,
        daemon: bool = False
    ) -> None:
        super().__init__()
        self.running = run_status
        self.network = network
        self.port = port
        self.handle_request_callback = request_handler
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if daemon:
            self.daemon = True
        self.socket.bind((self.network, self.port))
        self.network, self.port = self.socket.getsockname()
        self.socket.listen(5)
        self.threads: List[threading.Thread] = []

    def run(self) -> None:
        """
        Start the server thread and continuously check for incoming connections.

        :return: None
        """
        while self.running:
            readable = select.select([self.socket], [], [], 0.5)[0]
            if len(readable) == 1 and readable[0] is self.socket:
                server_thread = threading.Thread(target=self.handle_request, args=self.socket.accept())
                self.threads.append(server_thread)
                server_thread.start()
            time.sleep(0.1)

    def handle_request(self, client: Union[socket.socket, paramiko.Channel], addr: Tuple[str, int]) -> None:
        """
        Call the handle request callback for a new connection.

        :param client: The client's socket or paramiko channel.
        :type client: Union[socket.socket, paramiko.Channel]
        :param addr: Tuple containing the address information of the client.
        :type addr: Tuple[str, int]
        :return: None
        """
        if self.handle_request_callback is not None:
            self.handle_request_callback((self.network, self.port), client, addr)

    def close(self) -> None:
        """
        Join all the active threads and close the server socket.

        :return: None
        """
        for server_thread in self.threads:
            server_thread.join()
        self.socket.close()
